import base64
import json
import os.path
import subprocess
from typing import Dict, Optional, Any
from flask import Flask, jsonify, abort
from flask_restx import Api, Resource, fields
from kubernetes import client
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='Certificate Renewals EAG API',
    description='A Flask-based microservice for managing certificate renewals and operations in Kubernetes environments',
    doc='/swagger/'
)

# Configuration constants
CERT_FILE_PATH = "/opt/epaas/vault/secrets/certrenewalautomation_client_auth_cert.crt"
KEY_FILE_PATH = "/opt/epaas/vault/secrets/certrenewalautomation_client_private_key.key"
API_SERVER_URL = ""
SECRETS_FILE_PATH = "/opt/epaas/vault/secrets/secrets"
CACERTS_FILE_PATH = "/opt/epaas/vault/secrets/outbound_cacerts.json"
NAMESPACE = "gloo-system"

# Swagger models
health_model = api.model('Health', {
    'status': fields.String(required=True, description='Health status', example='healthy')
})

success_model = api.model('Success', {
    'status': fields.String(required=True, description='Operation status', example='success'),
    'message': fields.String(required=True, description='Success message')
})

error_model = api.model('Error', {
    'status': fields.String(required=True, description='Error status', example='error'),
    'message': fields.String(required=True, description='Error message')
})

cert_dates_model = api.model('CertificateDates', {
    'status': fields.String(required=True, description='Operation status', example='success'),
    'data': fields.String(required=True, description='Certificate date information')
})

cacerts_model = api.model('CACertificates', {
    'status': fields.String(required=True, description='Operation status', example='success'),
    'data': fields.Raw(required=True, description='CA certificates data')
})

k8s_status_model = api.model('KubernetesStatus', {
    'status': fields.String(required=True, description='Kubernetes client status')
})

def load_secrets(file_path: str) -> Dict[str, str]:
    secrets = {}
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    secrets[key] = value
    except Exception as e:
        logging.error(f"Error loading secrets: {e}")
    return secrets

def read_cert_files(crt_file_path: str = CERT_FILE_PATH, key_file_path: str = KEY_FILE_PATH) -> tuple[str, str]:
    with open(crt_file_path, 'r') as file:
        crt_content = file.read()
    with open(key_file_path, 'r') as file:
        key_content = file.read()
    
    crt_content = base64.b64decode(crt_content.encode('utf-8')).decode('utf-8')
    key_content = base64.b64decode(key_content.encode('utf-8')).decode('utf-8')
    
    return crt_content, key_content

def get_k8s_client() -> Optional[client.ApiClient]:
    token = app.config['SECRETS']['kube_token']
    
    if not token:
        logging.error("Kubernetes token is missing")
        return None
        
    return configure_k8s_client(token, API_SERVER_URL)

def configure_k8s_client(token: str, api_server_url: str) -> Optional[client.ApiClient]:
    try:
        configuration = client.Configuration()
        configuration.host = api_server_url
        configuration.verify_ssl = False
        configuration.api_key = {"authorization": f"Bearer {token}"}

        api_client = client.ApiClient(configuration)
        return api_client
    except Exception as e:
        logging.error(f"Error configuring k8s client: {e}")
        return None

@api.route('/health')
class HealthCheck(Resource):
    @api.doc('health_check', tags=['Health'])
    @api.marshal_with(health_model)
    @api.response(200, 'Service is healthy')
    def get(self):
        """Check the health status of the service"""
        return {'status': 'healthy'}, 200

@api.route('/test-k8s-client')
class TestKubernetesClient(Resource):
    @api.doc('test_k8s_client', tags=['Kubernetes'])
    @api.marshal_with(k8s_status_model)
    @api.response(200, 'Kubernetes client configured successfully')
    @api.response(500, 'Failed to configure Kubernetes client', error_model)
    def get(self):
        """Test Kubernetes client configuration and connectivity"""
        api_client = get_k8s_client()
        if not api_client:
            return {'status': 'failed to configure k8s client'}, 500

        try:
            v1 = client.CoreV1Api(api_client)
            v1.get_api_resources()
        except Exception as e:
            logging.error(f"Error validating k8s client: {e}")
            return {'status': 'failed to configure k8s client'}, 500

        return {'status': 'k8s client configured successfully'}, 200

@api.route('/create-certs')
class CreateCertificates(Resource):
    @api.doc('create_certs', tags=['Certificates'])
    @api.marshal_with(success_model)
    @api.response(200, 'Certificates created successfully')
    @api.response(500, 'Failed to create certificates', error_model)
    def post(self):
        """Create new TLS certificates in Kubernetes secret"""
        logging.info("Starting create_certs endpoint")

        api_client = get_k8s_client()
        if not api_client:
            logging.error("Failed to configure kubernetes client")
            abort(500)

        try:
            logging.info("Reading certificate files")
            crt_content, key_content = read_cert_files()

            secret_data = {
                'tls.crt': crt_content,
                'tls.key': key_content,
            }

            secret_metadata = client.V1ObjectMeta(name="custom-outbound-certs", namespace=NAMESPACE)
            secret = client.V1Secret(data=secret_data, metadata=secret_metadata, type="kubernetes.io/tls")

            v1 = client.CoreV1Api(api_client)
            v1.create_namespaced_secret(namespace=NAMESPACE, body=secret)
            logging.info("Successfully created secret")
            return {'status': 'success', 'message': 'certificates created successfully'}, 200
        except Exception as e:
            logging.error(f"Error creating certificates: {e}")
            abort(500, description=str(e))

@api.route('/renew-certs')
class RenewCertificates(Resource):
    @api.doc('renew_certs', tags=['Certificates'])
    @api.marshal_with(success_model)
    @api.response(200, 'Certificates renewed successfully')
    @api.response(500, 'Failed to renew certificates', error_model)
    def patch(self):
        """Renew existing TLS certificates in Kubernetes secret"""
        logging.info("Starting /renew-certs endpoint")

        api_client = get_k8s_client()
        if not api_client:
            logging.error("Failed to configure kubernetes client")
            abort(500)

        try:
            logging.info("Reading certificate files")
            crt_content, key_content = read_cert_files()

            data = {
                'data': {
                    'tls.crt': crt_content,
                    'tls.key': key_content,
                }
            }

            v1 = client.CoreV1Api(api_client)
            v1.patch_namespaced_secret(name="eag-client-certs", namespace=NAMESPACE, body=data)

            logging.info("Successfully patched secret")
            return {'status': 'success', 'message': 'Certificates renewed successfully'}, 200
        except Exception as e:
            logging.error(f"Error renewing certificates: {e}")
            abort(500, description=str(e))

@api.route('/check-cert-dates')
class CheckCertificateDates(Resource):
    @api.doc('check_cert_dates', tags=['Certificates'])
    @api.marshal_with(cert_dates_model)
    @api.response(200, 'Certificate dates retrieved successfully')
    @api.response(404, 'Certificate file not found', error_model)
    @api.response(500, 'Error checking certificate dates', error_model)
    def get(self):
        """Check certificate expiration dates using OpenSSL"""
        logging.info("Starting /check-cert-dates endpoint")
        if not os.path.exists(CERT_FILE_PATH):
            logging.error(f"File not found: {CERT_FILE_PATH}")
            return {
                "status": "error",
                "message": "Certificate file not found"
            }, 404

        try:
            logging.info("Executing openssl command to check certificate dates")
            command = ["openssl", "x509", "-in", CERT_FILE_PATH, "-noout", "-dates"]
            result = subprocess.run(command, capture_output=True, text=True, check=True)

            output = result.stdout.strip()
            logging.info("Successfully executed openssl command")

            return {
                "status": "success",
                "data": output
            }, 200
        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing openssl command: {e}")
            return {
                "status": "error",
                "message": "Error executing openssl command"
            }, 500
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            return {
                "status": "error",
                "message": "Internal server error"
            }, 500


@api.route('/read-cacerts')
class ReadCACertificates(Resource):
    @api.doc('read_cacerts', tags=['CA Certificates'])
    @api.marshal_with(cacerts_model)
    @api.response(200, 'CA certificates retrieved successfully')
    @api.response(404, 'CA certificates file not found', error_model)
    @api.response(400, 'Invalid JSON format', error_model)
    @api.response(500, 'Error reading CA certificates', error_model)
    def get(self):
        """Read and return CA certificate bundle data"""
        logging.info("Starting read_cacerts endpoint")
        if not os.path.exists(CACERTS_FILE_PATH):
            logging.error(f"File not found: {CACERTS_FILE_PATH}")
            return {
                "status": "error",
                "message": "CA certificates file not found"
            }, 404

        try:
            with open(CACERTS_FILE_PATH, 'r') as file:
                cacerts_content = json.load(file)
            logging.info("Successfully read json file")
            return {
                "status": "success",
                "data": cacerts_content
            }, 200
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing JSON file: {e}")
            return {
                "status": "error",
                "message": "Invalid JSON format"
            }, 400
        except Exception as e:
            logging.error(f"Error reading JSON file: {e}")
            return {
                "status": "error",
                "message": "Internal server error"
            }, 500

if __name__ == '__main__':
    def load():
        try:
            app.config['SECRETS'] = load_secrets(SECRETS_FILE_PATH)
        except Exception as e:
            print(f"Error loading secrets: {e}")
    load()
    app.run(debug=True, port=8080, host="0.0.0.0")

