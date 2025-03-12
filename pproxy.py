import argparse
import logging
import requests
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

"""

Proxies connections to the Letta API server.

"""


# Set up logging.
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('letta_proxy')

app = Flask(__name__)
CORS(app)

# Default configuration.
API_BASE_URL = "http://localhost:8283/v1"

# Parse command line arguments.
parser = argparse.ArgumentParser(description='Standalone API Proxy Server for Letta')
parser.add_argument('--port', type=int, default=8284, help='Port to run the proxy server on')
parser.add_argument('--api-url', type=str, default=API_BASE_URL, help='Base URL of the API to proxy')
parser.add_argument('--debug', action='store_true', help='Enable debug mode')
args = parser.parse_args()

# Update API URL from command line if provided.
API_BASE_URL = args.api_url

@app.route('/health')
def health():
    """Provides health check information for the proxy server.
    
    Returns:
        JSON: Server status, version, and target API information.
    """
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "proxy_version": "1.0.0",
        "target_api": API_BASE_URL
    })

@app.route('/set-target', methods=['POST'])
def set_target():
    """Changes the target API URL at runtime.
    
    This endpoint allows dynamic configuration of the API endpoint
    that the proxy forwards requests to. It validates the new URL
    before accepting it.
    
    Returns:
        JSON: Success or error message with status code.
    """
    """Change the target API URL at runtime"""
    global API_BASE_URL
    try:
        data = request.json
        new_url = data.get('url')
        if not new_url:
            return jsonify({"error": "Missing 'url' parameter"}), 400
            
        # Basic validation.
        if not new_url.startswith(('http://', 'https://')):
            return jsonify({"error": "URL must start with http:// or https://"}), 400
            
        # Test connection to new URL.
        try:
            # Remove trailing slash if present.
            base_url = new_url.rstrip('/')
            # Check if the URL already includes /v1.
            if not base_url.endswith('/v1'):
                health_url = f"{base_url}/v1/health/"
            else:
                health_url = f"{base_url}/health/"
                
            logger.info(f"Testing connection to: {health_url}")
            response = requests.get(health_url, timeout=3)
            
            if response.status_code != 200:
                return jsonify({"error": f"Connection test failed: {response.status_code}"}), 400
                
            # Update API URL.
            API_BASE_URL = new_url
            logger.info(f"API target changed to: {API_BASE_URL}")
            return jsonify({"status": "success", "target": API_BASE_URL})
            
        except requests.exceptions.RequestException as e:
            return jsonify({"error": f"Connection test failed: {str(e)}"}), 400
            
    except Exception as e:
        logger.error(f"Error setting target: {str(e)}")
        return jsonify({"error": str(e)}), 500

def set_cors_headers(response):
    """Set CORS headers to allow cross-origin requests."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Accept, Origin, User-Agent, Cache-Control, X-Requested-With'
    response.headers['Access-Control-Max-Age'] = '86400'
    response.headers['Access-Control-Expose-Headers'] = '*'
    return response

@app.after_request
def after_request(response):
    """Modify the response to include CORS headers."""
    return set_cors_headers(response)

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    """Main proxy function that forwards requests to the target API."""
    if request.method == 'OPTIONS':
        return set_cors_headers(jsonify({'status': 'ok'}))

    try:
        # Construct the target URL.
        if path.startswith('v1/'):
            path = path[3:]
        target_url = f"{API_BASE_URL}/{path}"
        logger.info(f"Proxying {request.method} request to: {target_url}")
        
        # Forward headers, excluding hop-by-hop headers.
        headers = {key: value for key, value in request.headers.items()
                  if key.lower() not in ('host', 'connection', 'content-length')}
        
        # Handle streaming..
        stream = 'stream' in path and request.method == 'POST'

        # Special handling for file uploads.
        if request.files:
            logger.debug("Handling file upload")
            file = next(iter(request.files.values()))
            logger.debug(f"Uploading file: {file.filename} ({file.content_type})")
            
            files = {'file': (file.filename, file.stream, file.content_type)}
            response = requests.post(
                url=target_url,
                files=files,
                headers={k: v for k, v in headers.items() if k.lower() != 'content-type'},
                params=request.args
            )
        else:
            # Handle other requests.
            kwargs = {
                'headers': headers,
                'params': request.args,
                'stream': stream
            }

            if request.method in ['POST', 'PUT', 'PATCH']:
                if request.is_json:
                    kwargs['json'] = request.json
                elif request.data:
                    kwargs['data'] = request.data

            response = requests.request(method=request.method, url=target_url, **kwargs)

        logger.debug(f"Response status: {response.status_code}")
        
        # Handle empty responses since DELETE sometimes have those.
        if not response.content:
            return '', response.status_code

        # Handle response.
        try:
            result = response.json()
            return jsonify(result), response.status_code
        except ValueError:
            return Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get('Content-Type', 'text/plain')
            )
            
    except Exception as e:
        logger.error(f"Proxy error: {str(e)}", exc_info=True)
        return jsonify({"error": f"Proxy error: {str(e)}"}), 500

if __name__ == '__main__':
    logger.info(f"Starting proxy server on port {args.port}")
    logger.info(f"Proxying requests to: {API_BASE_URL}")
    app.run(host='0.0.0.0', port=args.port, debug=args.debug)
