from flask import render_template, request, jsonify, redirect, url_for, session
from app import app, create_db_connection, make_api_request

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

@app.route('/processes')
def processes():
    app.logger.info("Accessed processes page")
    return render_template('processes.html')