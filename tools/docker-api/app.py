"""
Docker API Service for CyberLab UI
Flask-based API for managing Docker containers via docker-compose
"""

import subprocess
import json
import os
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Path to the docker-compose.yml file
DOCKER_COMPOSE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '../../docker')
)
DOCKER_COMPOSE_FILE = os.path.join(DOCKER_COMPOSE_PATH, 'docker-compose.yml')

# Service definitions matching the UI
SERVICE_DEFINITIONS = {
    'dvwa': {
        'name': 'DVWA',
        'container': 'lab-dvwa',
        'port': 8081,
        'category': 'web',
        'description': 'Damn Vulnerable Web Application'
    },
    'juice-shop': {
        'name': 'Juice Shop',
        'container': 'lab-juice-shop',
        'port': 8082,
        'category': 'web',
        'description': 'OWASP Juice Shop - Modern web app'
    },
    'webgoat': {
        'name': 'WebGoat',
        'container': 'lab-webgoat',
        'port': 8083,
        'category': 'web',
        'description': 'OWASP WebGoat - Guided lessons'
    },
    'bwapp': {
        'name': 'bWAPP',
        'container': 'lab-bwapp',
        'port': 8084,
        'category': 'web',
        'description': 'Buggy Web Application'
    },
    'mutillidae': {
        'name': 'Mutillidae',
        'container': 'lab-mutillidae',
        'port': 8085,
        'category': 'web',
        'description': 'OWASP Mutillidae II'
    },
    'mysql-vuln': {
        'name': 'MySQL',
        'container': 'lab-mysql-vuln',
        'port': 3307,
        'category': 'database',
        'description': 'Vulnerable MySQL with SQLi targets'
    },
    'postgres-vuln': {
        'name': 'PostgreSQL',
        'container': 'lab-postgres-vuln',
        'port': 5433,
        'category': 'database',
        'description': 'PostgreSQL with weak security'
    },
    'redis-vuln': {
        'name': 'Redis',
        'container': 'lab-redis-vuln',
        'port': 6380,
        'category': 'database',
        'description': 'Unauthenticated Redis'
    },
    'mongodb-vuln': {
        'name': 'MongoDB',
        'container': 'lab-mongodb-vuln',
        'port': 27018,
        'category': 'database',
        'description': 'NoSQL injection practice'
    },
    'vuln-ssh': {
        'name': 'Vulnerable SSH',
        'container': 'lab-vuln-ssh',
        'port': 2222,
        'category': 'service',
        'description': 'SSH with weak crypto & credentials'
    },
    'vuln-ftp': {
        'name': 'Vulnerable FTP',
        'container': 'lab-vuln-ftp',
        'port': 2121,
        'category': 'service',
        'description': 'FTP with anonymous access'
    },
    'buffer-overflow': {
        'name': 'Buffer Overflow',
        'container': 'lab-buffer-overflow',
        'port': 9999,
        'category': 'service',
        'description': 'Binary exploitation practice'
    }
}


def run_docker_compose(args: list[str], timeout: int = 30) -> tuple[bool, str]:
    """Run a docker-compose command and return success status and output."""
    try:
        cmd = ['docker-compose', '-f', DOCKER_COMPOSE_FILE] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=DOCKER_COMPOSE_PATH
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, 'Command timed out'
    except Exception as e:
        return False, str(e)


def get_container_status(container_name: str) -> str:
    """Get the status of a specific container."""
    try:
        result = subprocess.run(
            ['docker', 'inspect', '--format', '{{.State.Status}}', container_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            status = result.stdout.strip()
            if status == 'running':
                return 'running'
            elif status in ('created', 'restarting'):
                return 'starting'
            else:
                return 'stopped'
        return 'stopped'
    except Exception:
        return 'stopped'


def get_all_container_statuses() -> dict[str, str]:
    """Get status for all defined containers."""
    statuses = {}
    for service_id, service_info in SERVICE_DEFINITIONS.items():
        container_name = service_info['container']
        statuses[container_name] = get_container_status(container_name)
    return statuses


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    # Check if Docker is available
    try:
        result = subprocess.run(
            ['docker', 'info'],
            capture_output=True,
            timeout=5
        )
        docker_available = result.returncode == 0
    except Exception:
        docker_available = False

    # Check if docker-compose file exists
    compose_exists = os.path.isfile(DOCKER_COMPOSE_FILE)

    return jsonify({
        'status': 'healthy' if docker_available and compose_exists else 'degraded',
        'docker_available': docker_available,
        'compose_file_exists': compose_exists,
        'compose_path': DOCKER_COMPOSE_PATH
    })


@app.route('/services', methods=['GET'])
def get_services():
    """Get all services with their current status."""
    container_statuses = get_all_container_statuses()

    services = []
    for service_id, service_info in SERVICE_DEFINITIONS.items():
        container_name = service_info['container']
        services.append({
            'id': service_id,
            'name': service_info['name'],
            'container': container_name,
            'port': service_info['port'],
            'category': service_info['category'],
            'description': service_info['description'],
            'status': container_statuses.get(container_name, 'stopped')
        })

    return jsonify({
        'services': services,
        'running_count': sum(1 for s in services if s['status'] == 'running'),
        'total_count': len(services)
    })


@app.route('/services/<service_name>/start', methods=['POST'])
def start_service(service_name: str):
    """Start a specific service."""
    if service_name not in SERVICE_DEFINITIONS:
        return jsonify({'error': f'Unknown service: {service_name}'}), 404

    success, output = run_docker_compose(['up', '-d', service_name], timeout=120)

    if success:
        # Wait a moment and check status
        import time
        time.sleep(2)
        container_name = SERVICE_DEFINITIONS[service_name]['container']
        status = get_container_status(container_name)

        return jsonify({
            'success': True,
            'service': service_name,
            'status': status,
            'message': f'Service {service_name} started successfully'
        })
    else:
        return jsonify({
            'success': False,
            'service': service_name,
            'status': 'stopped',
            'error': output
        }), 500


@app.route('/services/<service_name>/stop', methods=['POST'])
def stop_service(service_name: str):
    """Stop a specific service."""
    if service_name not in SERVICE_DEFINITIONS:
        return jsonify({'error': f'Unknown service: {service_name}'}), 404

    success, output = run_docker_compose(['stop', service_name], timeout=60)

    if success:
        return jsonify({
            'success': True,
            'service': service_name,
            'status': 'stopped',
            'message': f'Service {service_name} stopped successfully'
        })
    else:
        return jsonify({
            'success': False,
            'service': service_name,
            'error': output
        }), 500


@app.route('/services/start-all', methods=['POST'])
def start_all_services():
    """Start all services."""
    success, output = run_docker_compose(['up', '-d'], timeout=300)

    if success:
        return jsonify({
            'success': True,
            'message': 'All services started successfully'
        })
    else:
        return jsonify({
            'success': False,
            'error': output
        }), 500


@app.route('/services/stop-all', methods=['POST'])
def stop_all_services():
    """Stop all services."""
    success, output = run_docker_compose(['stop'], timeout=120)

    if success:
        return jsonify({
            'success': True,
            'message': 'All services stopped successfully'
        })
    else:
        return jsonify({
            'success': False,
            'error': output
        }), 500


@app.route('/services/<service_name>/logs', methods=['GET'])
def get_service_logs(service_name: str):
    """Get logs for a specific service."""
    if service_name not in SERVICE_DEFINITIONS:
        return jsonify({'error': f'Unknown service: {service_name}'}), 404

    lines = request.args.get('lines', '100')
    success, output = run_docker_compose(['logs', '--tail', lines, service_name], timeout=30)

    return jsonify({
        'service': service_name,
        'logs': output
    })


if __name__ == '__main__':
    print(f"Docker Compose path: {DOCKER_COMPOSE_PATH}")
    print(f"Docker Compose file: {DOCKER_COMPOSE_FILE}")
    app.run(host='0.0.0.0', port=5001, debug=True)
