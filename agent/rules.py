# rule.py
import iptc
import logging
import ipaddress
import psutil
import pwd
import grp
import os
import spwd
import shutil
from pathlib import Path
import crypt
from functools import lru_cache
import re
import subprocess
import json

logging.basicConfig(filename='Rule.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def add_iptables_rule(protocol, destination_port, action):
    try:
        rule = iptc.Rule()
        rule.protocol = protocol.lower()
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")

        rule.create_target(action.upper())

        if protocol.lower() in ['tcp', 'udp']:
            match = rule.create_match(protocol.lower())
            match.dport = str(destination_port)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

        chain.insert_rule(rule)

        logger.info(f"Iptables rule added successfully: {protocol} {destination_port} {action}")
        return True
    except (iptc.IPTCError, ValueError) as e:
        logger.error(f"Error adding iptables rule: {e}")
        return False

def block_port(port):
    return add_iptables_rule("tcp", port, "DROP")

def inbound_rule(inbound_rule_data):
    try:
        rule = iptc.Rule()
        rule.protocol = inbound_rule_data['protocol'].lower()
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")

        logger.info(f"Received inbound rule data: {inbound_rule_data}")

        if rule.protocol in ['tcp', 'udp']:
            match = rule.create_match(rule.protocol)
            match.dport = str(inbound_rule_data['port'])

        if 'source_ip' in inbound_rule_data:
            ipaddress.ip_network(inbound_rule_data['source_ip'])  
            rule.src = inbound_rule_data['source_ip']

        rule.create_target("ACCEPT")
        chain.insert_rule(rule)

        logger.info("Inbound iptables rule added successfully")
        return True
    except Exception as e:
        logger.error(f"Error adding inbound iptables rule: {e}")
        return False

def outbound_rule(outbound_rule_data):
    try:
        rule = iptc.Rule()
        rule.protocol = outbound_rule_data['protocol'].lower()
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")

        logger.info(f"Received outbound rule data: {outbound_rule_data}")

        if rule.protocol in ['tcp', 'udp']:
            match = rule.create_match(rule.protocol)
            match.sport = str(outbound_rule_data['port'])

        if 'destination_ip' in outbound_rule_data:
            ipaddress.ip_network(outbound_rule_data['destination_ip'])  
            rule.dst = outbound_rule_data['destination_ip']

        rule.create_target("DROP")
        chain.insert_rule(rule)

        logger.info("Outbound iptables rule added successfully")
        return True
    except Exception as e:
        logger.error(f"Error adding outbound iptables rule: {e}")
        return False

def get_iptables_rules():
    try:
        # iptables-legacy
        legacy_check = subprocess.run(['sudo', 'iptables', '-L'], capture_output=True, text=True)
        use_legacy = "Warning: iptables-legacy tables present" in legacy_check.stderr

        iptables_cmd = 'iptables-legacy' if use_legacy else 'iptables'

        tables = ['filter', 'nat', 'mangle', 'raw']
        all_rules = {}

        for table in tables:
            result = subprocess.run(['sudo', iptables_cmd, '-t', table, '-L', '-n', '-v', '--line-numbers'],

                                    capture_output=True, text=True, check=True)

            chains = re.split(r'\nChain ', result.stdout)[1:]  
            table_rules = {}

            for chain in chains:
                chain_lines = chain.split('\n')
                chain_name = chain_lines[0].split()[0]
                policy_match = re.search(r'\(policy (\w+)\)', chain_lines[0])
                chain_policy = policy_match.group(1) if policy_match else 'N/A'

                rules = []
                for line in chain_lines[2:]:  
                    if line.strip() and not line.startswith('Chain'):
                        rule_parts = line.split()
                        if len(rule_parts) >= 8:
                            rule = {
                                'num': rule_parts[0],
                                'pkts': rule_parts[1],
                                'bytes': rule_parts[2],
                                'target': rule_parts[3],
                                'prot': rule_parts[4],
                                'opt': rule_parts[5],
                                'in': rule_parts[6],
                                'out': rule_parts[7],
                                'source': rule_parts[8] if len(rule_parts) > 8 else '',
                                'destination': rule_parts[9] if len(rule_parts) > 9 else '',
                                'options': ' '.join(rule_parts[10:]) if len(rule_parts) > 10 else ''
                            }
                            rules.append(rule)

                table_rules[chain_name] = {
                    'policy': chain_policy,
                    'rules': rules
                }

            all_rules[table] = table_rules

        return all_rules

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing iptables command: {e}")
        return {'error': f'Failed to retrieve iptables rules: {e}'}
    except Exception as e:
        logger.error(f"Unexpected error in get_iptables_rules: {e}")
        return {'error': f'Unexpected error occurred: {e}'}


@lru_cache(maxsize=None)
def get_running_processes():
    try:
        return [{'pid': proc.info['pid'], 'name': proc.info['name'], 'username': proc.info['username']}
                for proc in psutil.process_iter(['pid', 'name', 'username'])]
    except Exception as e:
        logger.error(f"Error getting running processes: {e}")
        return []

def add_user(username, password, groups=None):
    try:
        if pwd.getpwnam(username):
            return False, f"User {username} already exists"
    except KeyError:
        pass

    try:
        salt = os.urandom(6).hex()
        hashed_password = crypt.crypt(password, f'$6${salt}$')

        uids = [u.pw_uid for u in pwd.getpwall()]
        next_uid = max(uids) + 1 if uids else 1000

        new_user = f"{username}:x:{next_uid}:{next_uid}::/home/{username}:/bin/bash"

        with open('/etc/passwd', 'a') as passwd_file:
            passwd_file.write(new_user + '\n')

        with open('/etc/shadow', 'a') as shadow_file:
            shadow_file.write(f"{username}:{hashed_password}::0:99999:7:::\n")

        Path(f"/home/{username}").mkdir(mode=0o700, exist_ok=True)
        os.chown(f"/home/{username}", next_uid, next_uid)

        if groups:
            for group in groups:
                os.system(f"usermod -aG {group} {username}")

        logger.info(f"User {username} added successfully")
        return True, f"User {username} added successfully"
    except Exception as e:
        logger.error(f"Error adding user {username}: {e}")
        return False, f"Error adding user {username}: {e}"

def remove_user(username):
    try:
        user_info = pwd.getpwnam(username)
    except KeyError:
        return False, f"User {username} does not exist"

    try:
        os.system(f"userdel -r {username}")
        logger.info(f"User {username} removed successfully")
        return True, f"User {username} removed successfully"
    except Exception as e:
        logger.error(f"Error removing user {username}: {e}")
        return False, f"Error removing user {username}: {e}"


@lru_cache(maxsize=None)
def get_user_groups(username):
    groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
    gid = pwd.getpwnam(username).pw_gid
    groups.append(grp.getgrgid(gid).gr_name)
    return list(set(groups))

@lru_cache(maxsize=None)
def get_user_privileges(username):
    privileges = []
    if 'sudo' in get_user_groups(username):
        privileges.append('sudo')
    user_info = pwd.getpwnam(username)
    if user_info.pw_shell not in ['/usr/sbin/nologin', '/bin/false']:
        privileges.append('login')
    if os.path.exists('/etc/pam.d/su'):
        with open('/etc/pam.d/su', 'r') as f:
            if any('pam_wheel.so' in line for line in f) and 'wheel' in get_user_groups(username):
                privileges.append('su to root')
    return privileges

def get_non_default_users():
    try:
        non_default_users = []
        for user in pwd.getpwall():
            if 1000 <= user.pw_uid < 65534 and user.pw_shell not in ['/usr/sbin/nologin', '/bin/false']:
                user_info = {
                    'username': user.pw_name,
                    'uid': user.pw_uid,
                    'gid': user.pw_gid,
                    'home': user.pw_dir,
                    'shell': user.pw_shell,
                    'groups': get_user_groups(user.pw_name),
                    'privileges': get_user_privileges(user.pw_name)
                }
                try:
                    sp = spwd.getspnam(user.pw_name)
                    user_info.update({
                        'last_password_change': sp.sp_lstchg,
                        'min_password_age': sp.sp_min,
                        'max_password_age': sp.sp_max
                    })
                except KeyError:
                    pass
                non_default_users.append(user_info)
        return non_default_users
    except Exception as e:
        logger.error(f"Error getting non-default users: {e}")
        return []


def get_installed_applications():
    applications = set()

    def add_to_applications(app):
        if app and len(app) > 1:  
            applications.add(app.strip())

    # Scaning .desktop files
    try:
        for desktop_file in Path('/usr/share/applications').glob('*.desktop'):
            with open(desktop_file, 'r', errors='ignore') as f:
                content = f.read()
                match = re.search(r'^Name=(.+)$', content, re.MULTILINE)
                if match:
                    add_to_applications(match.group(1))
    except Exception as e:
        logger.error(f"Error scanning desktop files: {e}")

    # Using 'dpkg' for Debian-based systems
    try:
        result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
        for line in result.stdout.split('\n')[5:]:  
            parts = line.split()
            if len(parts) >= 2:
                add_to_applications(parts[1])
    except Exception as e:
        logger.error(f"Error using dpkg: {e}")

    # Using 'rpm' for Red Hat-based systems
    try:
        result = subprocess.run(['rpm', '-qa'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            add_to_applications(line)
    except Exception as e:
        logger.error(f"Error using rpm: {e}")

    # Scaning /usr/bin and /usr/local/bin
    for bin_dir in ['/usr/bin', '/usr/local/bin']:
        try:
            for file in os.listdir(bin_dir):
                if os.path.isfile(os.path.join(bin_dir, file)) and os.access(os.path.join(bin_dir, file), os.X_OK):
                    add_to_applications(file)
        except Exception as e:
            logger.error(f"Error scanning {bin_dir}: {e}")

    # List system services
    try:
        result = subprocess.run(['systemctl', 'list-units', '--type=service', '--all'], capture_output=True, text=True)
        for line in result.stdout.split('\n')[1:]:  
            parts = line.split()
            if len(parts) >= 5:
                service_name = parts[0].replace('.service', '')
                add_to_applications(service_name)
    except Exception as e:
        logger.error(f"Error listing system services: {e}")

    return sorted(list(applications))