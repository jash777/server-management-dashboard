# Server Management Dashboard

A centralized dashboard for comprehensive server management, including firewall rules, server activity monitoring, user management, service tracking, and processor performance analysis.

## Features

- **Firewall Management**: View and modify firewall rules across multiple servers.
- **Server Activity Monitoring**: Real-time tracking of server performance and events.
- **User Management**: Centralized control over user accounts and permissions.
- **Service Tracking**: Monitor and manage running services on all connected servers.
- **Processor Performance**: Real-time CPU usage and performance metrics.

## Installation

```bash
git clone https://github.com/yourusername/server-management-dashboard.git
cd server-management-dashboard
pip install -r requirements.txt
```

## Usage

1. Configure your server connections in `config.yml`.
2. Run the dashboard:

```bash
python main.py
```

3. Access the web interface at `http://localhost:8080`.

## Configuration

Edit `config.yml` to add your server details:

```yaml
servers:
  - name: Production Server
    host: 192.168.1.100
    port: 22
    username: admin
  - name: Development Server
    host: 192.168.1.101
    port: 22
    username: devuser
```

## Dependencies

- Python 3.8+
- Flask
- Paramiko
- psutil
- PyYAML

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please open an issue on the GitHub repository or contact the maintainer at support@example.com.
