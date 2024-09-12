import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import mysql.connector
from mysql.connector import Error
import os
from datetime import datetime
import requests

# Configure logging
logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Set a secret key for session management

# MySQL Configuration
db_config = {
    'host': '192.168.1.28',
    'user': 'dev',
    'password': 'olivia#777',
    'database': 'alpha'
}

API_KEY = os.environ.get('API_KEY', 'alpha')
AGENT_PORT = 5000  # Default port for the agent

# Database connection function
def create_db_connection():
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except Error as e:
        app.logger.error(f"Error connecting to MySQL: {e}")
        return None

# Helper function for API requests
def make_api_request(endpoint, method='GET', data=None):
    if 'selected_agent' not in session:
        app.logger.warning("API request attempted without a selected agent")
        return jsonify({'error': 'No agent selected'}), 400

    headers = {'X-API-Key': API_KEY}
    url = f"http://{session['selected_agent']}:{AGENT_PORT}/{endpoint}"
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=5)
        elif method == 'POST':
            response = requests.post(url, json=data, headers=headers, timeout=5)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, timeout=5)
        
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        app.logger.error(f"Error communicating with agent: {str(e)}")
        return jsonify({'error': f'Error communicating with agent: {str(e)}'}), 500

# Routes
@app.route('/')
def index():
    app.logger.info("Accessed home page")
    return render_template('index.html')

@app.route('/agents')
def agents():
    app.logger.info("Accessed agents page")
    connection = create_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM agents")
        agents = cursor.fetchall()
        cursor.close()
        connection.close()
        return render_template('agents.html', agents=agents)
    app.logger.error("Database connection error in agents route")
    return "Database connection error", 500

@app.route('/select_agent/<int:agent_id>', methods=['POST'])
def select_agent(agent_id):
    try:
        connection = create_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM agents WHERE id = %s", (agent_id,))
            agent = cursor.fetchone()
            cursor.close()
            connection.close()
            
            if agent:
                session['selected_agent'] = agent['ip_address']
                session['selected_agent_name'] = agent['name']
                app.logger.info(f"Agent selected: {agent['name']} ({agent['ip_address']})")
                return jsonify({'message': 'Agent selected successfully', 'agent': agent['name']}), 200
            else:
                app.logger.warning(f"Attempted to select non-existent agent with ID: {agent_id}")
                return jsonify({'error': 'Agent not found'}), 404
        else:
            app.logger.error("Database connection error in select_agent route")
            return jsonify({'error': 'Database connection error'}), 500
    except Exception as e:
        app.logger.error(f"Error in select_agent route: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/users')
def users():
    app.logger.info("Accessed users page")
    users = make_api_request('users')
    return render_template('users.html', users=users.get('users', []))

@app.route('/applications')
def applications():
    app.logger.info("Accessed applications page")
    apps = make_api_request('applications')
    return render_template('applications.html', applications=apps.get('applications', []))

@app.route('/firewall')
def firewall():
    app.logger.info("Accessed firewall page")
    connection = create_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM firewall_rules")
        rules = cursor.fetchall()
        cursor.close()
        connection.close()
        return render_template('firewall.html', rules=rules)
    app.logger.error("Database connection error in firewall route")
    return "Database connection error", 500

# API Routes
@app.route('/api/agents', methods=['GET', 'POST', 'DELETE'])
def manage_agents():
    app.logger.info(f"Managing agents - Method: {request.method}")
    connection = create_db_connection()
    if not connection:
        app.logger.error("Database connection error in manage_agents route")
        return jsonify({'error': 'Database connection error'}), 500

    cursor = connection.cursor(dictionary=True)

    if request.method == 'GET':
        cursor.execute("SELECT * FROM agents")
        agents = cursor.fetchall()
        cursor.close()
        connection.close()
        return jsonify(agents)

    elif request.method == 'POST':
        data = request.json
        query = "INSERT INTO agents (name, ip_address, status) VALUES (%s, %s, %s)"
        values = (data['name'], data['ip_address'], 'Unknown')
        cursor.execute(query, values)
        connection.commit()
        cursor.close()
        connection.close()
        app.logger.info(f"Added new agent: {data['name']} ({data['ip_address']})")
        return jsonify({'message': 'Agent added successfully'}), 201

    elif request.method == 'DELETE':
        agent_id = request.args.get('id')
        query = "DELETE FROM agents WHERE id = %s"
        cursor.execute(query, (agent_id,))
        connection.commit()
        cursor.close()
        connection.close()
        app.logger.info(f"Removed agent with ID: {agent_id}")
        return jsonify({'message': 'Agent removed successfully'}), 200

@app.route('/api/check_agent_status/<int:agent_id>')
def check_agent_status(agent_id):
    app.logger.info(f"Checking status of agent with ID: {agent_id}")
    connection = create_db_connection()
    if not connection:
        app.logger.error("Database connection error in check_agent_status route")
        return jsonify({'error': 'Database connection error'}), 500

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM agents WHERE id = %s", (agent_id,))
    agent = cursor.fetchone()

    if not agent:
        cursor.close()
        connection.close()
        app.logger.warning(f"Attempted to check status of non-existent agent with ID: {agent_id}")
        return jsonify({'error': 'Agent not found'}), 404
    
    import random
    new_status = random.choice(['Active', 'Inactive', 'Unreachable'])
    
    update_query = "UPDATE agents SET status = %s, last_check = %s WHERE id = %s"
    cursor.execute(update_query, (new_status, datetime.now(), agent_id))
    connection.commit()

    cursor.close()
    connection.close()
    app.logger.info(f"Updated status of agent {agent_id} to {new_status}")
    return jsonify({'status': new_status})

@app.route('/processes')
def processes():
    app.logger.info("Accessed processes page")
    return render_template('processes.html')

@app.route('/api/processes')
def get_processes():
    if 'selected_agent' not in session:
        return jsonify({'error': 'No agent selected'}), 400

    agent_url = f"http://{session['selected_agent']}:{AGENT_PORT}/processes"
    
    try:
        response = requests.get(agent_url, headers={'X-API-Key': API_KEY}, timeout=5)
        response.raise_for_status()
        processes = response.json()
        
        if not processes:
            return jsonify({'error': 'Processes not enabled for this agent'}), 404
        
        return jsonify(processes)
    except requests.RequestException as e:
        app.logger.error(f"Error communicating with agent for processes: {str(e)}")
        return jsonify({'error': f'Error communicating with agent: {str(e)}'}), 500

@app.route('/api/users', methods=['GET', 'POST', 'DELETE'])
def manage_users():
    app.logger.info(f"Managing users - Method: {request.method}")
    if request.method == 'GET':
        return make_api_request('users')
    elif request.method == 'POST':
        return make_api_request('add_user', method='POST', data=request.json)
    elif request.method == 'DELETE':
        return make_api_request(f"remove_user?username={request.args.get('username')}", method='DELETE')

@app.route('/api/applications')
def get_applications():
    app.logger.info("Fetching applications from agent")
    return make_api_request('applications')

@app.route('/api/firewall_rules', methods=['GET', 'POST', 'DELETE'])
def manage_firewall_rules():
    app.logger.info(f"Managing firewall rules - Method: {request.method}")
    if request.method == 'GET':
        connection = create_db_connection()
        if not connection:
            app.logger.error("Database connection error in manage_firewall_rules route (GET)")
            return jsonify({'error': 'Database connection error'}), 500

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM firewall_rules")
        rules = cursor.fetchall()
        cursor.close()
        connection.close()
        return jsonify(rules)

    elif request.method == 'POST':
        return make_api_request('apply-rules', method='POST', data={'rules': [request.json]})

    elif request.method == 'DELETE':
        connection = create_db_connection()
        if not connection:
            app.logger.error("Database connection error in manage_firewall_rules route (DELETE)")
            return jsonify({'error': 'Database connection error'}), 500

        cursor = connection.cursor(dictionary=True)
        rule_id = request.args.get('id')
        query = "DELETE FROM firewall_rules WHERE id = %s"
        cursor.execute(query, (rule_id,))
        connection.commit()
        cursor.close()
        connection.close()
        app.logger.info(f"Removed firewall rule with ID: {rule_id}")
        return jsonify({'message': 'Firewall rule removed successfully'}), 200

@app.route('/api/block_port', methods=['POST'])
def block_port():
    app.logger.info("Blocking port on agent")
    return make_api_request('block_port', method='POST', data=request.json)

@app.route('/api/selected_agent')
def get_selected_agent():
    app.logger.info("Fetching selected agent information")
    if 'selected_agent' in session and 'selected_agent_name' in session:
        return jsonify({
            'selected_agent': {
                'name': session['selected_agent_name'],
                'ip_address': session['selected_agent']
            }
        })
    else:
        app.logger.warning("No agent currently selected")
        return jsonify({'selected_agent': None})

if __name__ == '__main__':
    app.run(debug=True, port=5001)