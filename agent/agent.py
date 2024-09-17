# agent.py
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from rules import *
import logging
from functools import wraps
import json
import os
import json

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

logging.basicConfig(filename='agent.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != os.environ.get('API_KEY', 'alpha'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def agent_status():
    return "<h1>Agent is running</h1>"

@app.route('/apply-rules', methods=['POST'])
@require_api_key
def apply_rules():
    rules = request.json.get('rules', [])
    results = [{'rule': rule, 'success': add_iptables_rule(rule['protocol'], rule['destination_port'], rule['action'])}
               for rule in rules]
    return jsonify({'status': 'completed', 'results': results})

@app.route('/inbound_rule', methods=['POST'])
@require_api_key
def inbound_rules():
    inbound_rule_data = request.json.get('inbound_rule')
    if not inbound_rule_data:
        return jsonify({'error': 'No inbound rule data provided'}), 400
    success = inbound_rule(inbound_rule_data)
    return jsonify({'status': 'success' if success else 'failed'})

@app.route('/outbound_rule', methods=['POST'])
@require_api_key
def outbound_rules():
    outbound_rule_data = request.json.get('outbound_rule')
    if not outbound_rule_data:
        return jsonify({'error': 'No outbound rule data provided'}), 400
    success = outbound_rule(outbound_rule_data)
    return jsonify({'status': 'success' if success else 'failed'})

@app.route('/block_port', methods=['POST'])
@require_api_key
def block_port_route():
    port = request.json.get('port')
    if not port:
        return jsonify({"error": "port is required"}), 400
    try:
        port = int(port)
        success = block_port(port)
        return jsonify({"message": f"port {port} blocked" if success else f"Failed to block port {port}"})
    except ValueError:
        return jsonify({"error": "port must be a number"}), 400

@app.route('/iptables_rules')
@require_api_key
def get_iptables_rules_route():
    try:
        rules = get_iptables_rules()
        if isinstance(rules, dict) and 'error' in rules:
            logger.error(f"Error retrieving iptables rules: {rules['error']}")
            return jsonify({
                'status': 'error',
                'message': rules['error']
            }), 500
        return jsonify({
            'status': 'success',
            'rules': rules
        })
    except Exception as e:
        logger.error(f"Unexpected error in get_iptables_rules route: {e}")
        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred while retrieving iptables rules',
            'error': str(e)
        }), 500

@app.route('/processes')
@require_api_key
def get_processes():
    return jsonify(get_running_processes())


@app.route('/add_user', methods=['POST'])
@require_api_key
def add_user_route():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    groups = data.get('groups', [])

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    success, message = add_user(username, password, groups)
    return jsonify({'message': message}), 200 if success else 400

@app.route('/remove_user', methods=['POST'])
@require_api_key
def remove_user_route():
    username = request.json.get('username')
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    success, message = remove_user(username)
    return jsonify({'message': message}), 200 if success else 400

@app.route('/users', methods=['GET'])
@require_api_key
def get_users_route():
    return jsonify({'users': get_non_default_users()})

def send_process_data():
    while True:
        socketio.emit('process_data', json.dumps(get_running_processes()))
        socketio.sleep(60)  # Update every 60 seconds

@app.route('/applications')
@require_api_key
def get_applications():
    try:
        applications = get_installed_applications()
        return jsonify({
            'status': 'success',
            'count': len(applications),
            'applications': applications
        })
    except Exception as e:
        logger.error(f"Error in get_applications route: {e}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while retrieving installed applications',
            'error': str(e)
        }), 500

@socketio.on('connect')
def handle_connect():
    socketio.start_background_task(send_process_data)

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)