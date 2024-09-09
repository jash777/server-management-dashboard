from flask import Flask, render_template, request, jsonify, redirect, url_for
import mysql.connector
from mysql.connector import Error
import os
from datetime import datetime
import requests

app = Flask(__name__)

# MySQL Configuration
db_config = {
    'host': '192.168.1.28',
    'user': 'dev',
    'password': 'olivia#777',
    'database': 'alpha'
}

API_KEY = os.environ.get('API_KEY', 'alpha')
BACKEND_URL = "http://172.24.110.124:5000"  # Update this with your backend URL

# Database connection function
def create_db_connection():
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Helper function for API requests
def make_api_request(endpoint, method='GET', data=None):
    headers = {'X-API-Key': API_KEY}
    url = f"{BACKEND_URL}/{endpoint}"
    
    if method == 'GET':
        response = requests.get(url, headers=headers)
    elif method == 'POST':
        response = requests.post(url, json=data, headers=headers)
    elif method == 'DELETE':
        response = requests.delete(url, headers=headers)
    
    return response.json()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/agents')
def agents():
    connection = create_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM agents")
        agents = cursor.fetchall()
        cursor.close()
        connection.close()
        return render_template('agents.html', agents=agents)
    return "Database connection error", 500

@app.route('/processes')
def processes():
    processes = make_api_request('processes')
    return render_template('processes.html', processes=processes)

@app.route('/users')
def users():
    users = make_api_request('users')
    return render_template('users.html', users=users.get('users', []))

@app.route('/applications')
def applications():
    apps = make_api_request('applications')
    return render_template('applications.html', applications=apps.get('applications', []))

@app.route('/firewall')
def firewall():
    connection = create_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM firewall_rules")
        rules = cursor.fetchall()
        cursor.close()
        connection.close()
        return render_template('firewall.html', rules=rules)
    return "Database connection error", 500

# API Routes
@app.route('/api/agents', methods=['GET', 'POST', 'DELETE'])
def manage_agents():
    connection = create_db_connection()
    if not connection:
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
        return jsonify({'message': 'Agent added successfully'}), 201

    elif request.method == 'DELETE':
        agent_id = request.args.get('id')
        query = "DELETE FROM agents WHERE id = %s"
        cursor.execute(query, (agent_id,))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({'message': 'Agent removed successfully'}), 200

@app.route('/api/check_agent_status/<int:agent_id>')
def check_agent_status(agent_id):
    connection = create_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM agents WHERE id = %s", (agent_id,))
    agent = cursor.fetchone()

    if not agent:
        cursor.close()
        connection.close()
        return jsonify({'error': 'Agent not found'}), 404
    
    # Here you would typically check the agent's status
    # For this example, we'll just update it randomly
    import random
    new_status = random.choice(['Active', 'Inactive', 'Unreachable'])
    
    update_query = "UPDATE agents SET status = %s, last_check = %s WHERE id = %s"
    cursor.execute(update_query, (new_status, datetime.now(), agent_id))
    connection.commit()

    cursor.close()
    connection.close()
    return jsonify({'status': new_status})

@app.route('/api/processes')
def get_processes():
    return make_api_request('processes')

@app.route('/api/users', methods=['GET', 'POST', 'DELETE'])
def manage_users():
    if request.method == 'GET':
        return make_api_request('users')
    elif request.method == 'POST':
        return make_api_request('add_user', method='POST', data=request.json)
    elif request.method == 'DELETE':
        return make_api_request(f"remove_user?username={request.args.get('username')}", method='POST')

@app.route('/api/applications')
def get_applications():
    return make_api_request('applications')

@app.route('/api/firewall_rules', methods=['GET', 'POST', 'DELETE'])
def manage_firewall_rules():
    if request.method == 'GET':
        connection = create_db_connection()
        if not connection:
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
            return jsonify({'error': 'Database connection error'}), 500

        cursor = connection.cursor(dictionary=True)
        rule_id = request.args.get('id')
        query = "DELETE FROM firewall_rules WHERE id = %s"
        cursor.execute(query, (rule_id,))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({'message': 'Firewall rule removed successfully'}), 200

@app.route('/api/block_port', methods=['POST'])
def block_port():
    return make_api_request('block_port', method='POST', data=request.json)

if __name__ == '__main__':
    app.run(debug=True, port=5001)