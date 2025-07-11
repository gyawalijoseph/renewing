# Certificate Renewals EAG

A Flask-based microservice for managing certificate renewals and operations in Kubernetes environments. This service provides RESTful APIs for creating, renewing, and monitoring TLS certificates stored as Kubernetes secrets.

## Features

- **Certificate Management**: Create and renew TLS certificates in Kubernetes secrets
- **Certificate Monitoring**: Check certificate expiration dates using OpenSSL
- **CA Certificates**: Read and manage CA certificate bundles
- **Health Checks**: Built-in health check endpoint for monitoring
- **Kubernetes Integration**: Full integration with Kubernetes API for secret management

## Architecture

The application is designed to run in a containerized environment with the following components:

- **Flask Application**: Main web service providing REST APIs
- **Kubernetes Client**: Manages secrets in Kubernetes clusters
- **Certificate Processing**: Handles Base64 encoded certificate files
- **Configuration Management**: Centralized configuration for paths and settings

## API Endpoints

### Health Check
```
GET /health
```
Returns the health status of the service.

**Response:**
```json
{
  "status": "healthy"
}
```

### Test Kubernetes Client
```
GET /test-k8s-client
```
Validates the Kubernetes client configuration and connectivity.

**Response:**
```json
{
  "status": "k8s client configured successfully"
}
```

### Create Certificates
```
POST /create-certs
```
Creates a new TLS secret in Kubernetes with certificate data.

**Response:**
```json
{
  "status": "success",
  "message": "certificates created successfully"
}
```

### Renew Certificates
```
PATCH /renew-certs
```
Updates an existing TLS secret with renewed certificate data.

**Response:**
```json
{
  "status": "success",
  "message": "Certificates renewed successfully"
}
```

### Check Certificate Dates
```
GET /check-cert-dates
```
Retrieves certificate expiration information using OpenSSL.

**Response:**
```json
{
  "status": "success",
  "data": "notBefore=Jan  1 00:00:00 2024 GMT\nnotAfter=Dec 31 23:59:59 2024 GMT"
}
```

### Read CA Certificates
```
GET /read-cacerts
```
Reads and returns CA certificate bundle data.

**Response:**
```json
{
  "status": "success",
  "data": {
    // CA certificate data
  }
}
```

## Configuration

The application uses the following configuration constants:

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `CERT_FILE_PATH` | Path to the TLS certificate file | `/opt/epaas/vault/secrets/certrenewalautomation_client_auth_cert.crt` |
| `KEY_FILE_PATH` | Path to the private key file | `/opt/epaas/vault/secrets/certrenewalautomation_client_private_key.key` |
| `API_SERVER_URL` | Kubernetes API server URL | `https://api.cld-paas-d-eusw1b-3.phx.aexp.com:6443` |
| `SECRETS_FILE_PATH` | Path to secrets configuration | `/opt/epaas/vault/secrets/secrets` |
| `CACERTS_FILE_PATH` | Path to CA certificates | `/opt/epaas/vault/secrets/outbound_cacerts.json` |
| `NAMESPACE` | Target Kubernetes namespace | `gloo-system` |

## Dependencies

The application requires the following Python packages:

- `Flask`: Web framework for creating REST APIs
- `kubernetes`: Python client for Kubernetes API
- `requests`: HTTP library for external requests

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd cert-renewals-eag
   ```

2. **Install dependencies:**
   ```bash
   pip install -r packages.txt
   ```

3. **Set up secrets:**
   Ensure the following files are available:
   - Kubernetes token in secrets file
   - TLS certificate and private key files
   - CA certificates JSON file

4. **Run the application:**
   ```bash
   python app.py
   ```

The application will start on `http://0.0.0.0:8080` with debug mode enabled.

## Docker Deployment

The application includes a `entrypoint.sh` script for containerized deployments and Helm charts for Kubernetes deployment.

### Helm Configuration

The application can be deployed using Helm with the provided `values_e1.yaml` configuration:

- **Container Port**: 8080
- **Health Check**: `/health` endpoint
- **Resources**: 
  - CPU: 250m (request), 1 (limit)
  - Memory: 1.5G (request), 4G (limit)
- **Auto Scaling**: HPA enabled with 75% CPU utilization threshold

## Security Considerations

- All certificate files are Base64 encoded for secure storage
- Kubernetes RBAC permissions required for secret management
- SSL verification is disabled for internal cluster communication
- Sensitive data is loaded from secure vault locations

## Error Handling

The application provides comprehensive error handling with:

- Consistent JSON error responses
- Appropriate HTTP status codes
- Detailed logging for troubleshooting
- Graceful degradation when services are unavailable

## Monitoring

- Health check endpoint for service monitoring
- Comprehensive logging throughout the application
- Kubernetes readiness probes configured
- Support for external monitoring systems

## Development

### Running Locally

1. Set up a local Kubernetes cluster or configure access to a remote cluster
2. Ensure all required certificate files are available
3. Configure the secrets file with appropriate tokens
4. Run the Flask application in debug mode

### Testing

Use the `/test-k8s-client` endpoint to verify Kubernetes connectivity before performing certificate operations.

## Contributing

1. Follow the existing code structure and naming conventions
2. Add appropriate type hints to all functions
3. Include comprehensive error handling
4. Update documentation for any new endpoints or features
5. Test all changes thoroughly before submitting

## License

[License information to be added based on organization requirements]# renewing
