import argparse
import logging
import requests
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
import json
import sqlite3

"""

Proxies connections to the Letta API server.

"""

# Set up logging with debug level and formatted timestamp output.
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('letta_proxy')
logger.setLevel(logging.DEBUG) 

app = Flask(__name__)
CORS(app)

API_BASE_URL = "http://localhost:8283/v1"

# Parse command line arguments to configure the server.
parser = argparse.ArgumentParser(description='Standalone API Proxy Server for Letta')
parser.add_argument('--port', type=int, default=8284, help='Port to run the proxy server on')
parser.add_argument('--api-url', type=str, default=API_BASE_URL, help='Base URL of the API to proxy')
parser.add_argument('--debug', action='store_true', help='Enable debug mode')
parser.add_argument('--require-token', action='store_true', help='Require a token for proxy access')  # New flag for token requirement
# require ssl.
parser.add_argument('--ssl', action='store_true', help='Require SSL for proxy access')

args = parser.parse_args()

# Update API URL if provided via command line arguments.
if args.api_url:
    API_BASE_URL = args.api_url

#@app.route('/set-target', methods=['POST'])
def set_target(url=None):
    # Docstring format documentation.
    """
    Changes the target API URL at runtime.

    Can be called either as a Flask route handler or directly with a URL parameter.

    Args:
        url (str): The new target API URL to set.

    Returns:
        dict: A JSON response indicating the success or failure of the operation.
    """
    global API_BASE_URL
    try:
        if url:
            new_url = url
        else:
            data = request.json
            new_url = data.get('url')
            
        if not new_url:
            return jsonify({"error": "Missing 'url' parameter"}), 400
            
        # Basic validation
        if not new_url.startswith(('http://', 'https://')):
            return jsonify({"error": "URL must start with http:// or https://"}), 400
            
        # Test connection to new URL
        try:
            base_url = new_url.rstrip('/')
            if not base_url.endswith('/v1'):
                health_url = f"{base_url}/v1/health/"
            else:
                health_url = f"{base_url}/health/"
                
            logger.info(f"Testing connection to: {health_url}")
            response = requests.get(health_url, timeout=3)
            
            if response.status_code != 200:
                return jsonify({"error": f"Connection test failed: {response.status_code}"}), 400
                
            # Update API URL
            API_BASE_URL = new_url
            logger.info(f"API target changed to: {API_BASE_URL}")

            # Load tokens from SQLite into the in-memory set.
            load_tokens_into_memory()

            return jsonify({"status": "success", "target": API_BASE_URL})
            
        except requests.exceptions.RequestException as e:
            return jsonify({"error": f"Connection test failed: {str(e)}"}), 400
            
    except Exception as e:
        logger.error(f"Error setting target: {str(e)}")
        return jsonify({"error": str(e)}), 500

# In-memory set for fast token access
valid_tokens = set()


def load_tokens_into_memory():

    """
    Load tokens from SQLite into the in-memory set.

    Args:
        None

    Returns:
        None
    """
    global valid_tokens
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    cursor.execute('SELECT token FROM tokens')
    tokens = cursor.fetchall()
    valid_tokens = {token[0] for token in tokens}  # Load tokens into the set
    conn.close()

def add_token(token):

    """
    Add a token to the SQLite database and in-memory set.

    Args:
        token (str): The token to add.

    Returns:
        None
    """
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO tokens (token) VALUES (?)', (token,))
        conn.commit()
        valid_tokens.add(token)  # Add to in-memory set
    except sqlite3.IntegrityError:
        print("Token already exists.")
    finally:
        conn.close()

def validate_token(token):
    """
    Validate a token against the in-memory set and SQLite database.

    Args:
        token (str): The token to validate.

    Returns:
        bool: True if the token is valid, False otherwise.
    """
    if token in valid_tokens:
        return True
    # Fallback to SQLite if not found in memory
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tokens WHERE token = ?', (token,))
    valid = cursor.fetchone() is not None
    conn.close()
    if valid:
        valid_tokens.add(token)  # Add to in-memory set for future access
    return valid

def set_cors_headers(response):
    """
    Set CORS headers to allow cross-origin requests.

    Args:
        response: The Flask response object.

    Returns:
        The modified response object with CORS headers set.
    """
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Max-Age'] = '86400'
    response.headers['Access-Control-Expose-Headers'] = '*'
    return response

@app.after_request
def after_request(response):
    """
    Modify the response to include CORS headers.

    Args:
        response: The Flask response object.

    Returns:
        The modified response object with CORS headers set.
    """
    response = set_cors_headers(response)
    # For streaming responses, ensure no-cache headers are set.
    if response.mimetype == 'text/event-stream':
        response.headers.update({
            'Cache-Control': 'no-cache, no-transform, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'X-Accel-Buffering': 'no'
        })
    
    return response

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    """
    Proxy requests to the target API.

    Args:
        path (str): The path to proxy.
    """
    if request.method == 'OPTIONS':
        return set_cors_headers(jsonify({'status': 'ok'}))

    # Check for token in headers if required
    if args.require_token:
        token = request.headers.get('Authorization')
        if not token or not validate_token(token):
            return jsonify({"error": "Unauthorized: Invalid or missing token"}), 401

    try:
        # Construct the target URL.
        if path.startswith('v1/'):
            path = path[3:]
        target_url = f"{API_BASE_URL}/{path}"
        logger.info(f"Proxying {request.method} request to: {target_url}")
        
        # Log complete request details, excluding the Authorization header.
        headers_to_log = {key: value for key, value in request.headers.items() if key.lower() != 'authorization'}
        logger.debug(f"Request headers: {dict(headers_to_log)}")
        logger.debug(f"Request query params: {dict(request.args)}")
        if request.is_json:
            logger.debug(f"Request JSON body: {request.json}")
        elif request.data:
            logger.debug(f"Request raw body: {request.data}")
        
        # Forward headers while excluding hop-by-hop headers that should not be proxied.
        headers = {key: value for key, value in request.headers.items()
                  if key.lower() not in ('host', 'connection', 'content-length')}
        
        # This proxy primarily handles streaming requests for chat interfaces using Server-Sent Events.
        stream = 'messages/stream' in path and request.method == 'POST'
        
        # Initialize response variable to avoid undefined references later.
        response = None

        # Special handling for file upload requests.
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
            # Handle other standard API requests.
            kwargs = {
                'headers': headers,
                'params': request.args
            }

            if request.method in ['POST', 'PUT', 'PATCH']:
                if request.is_json:
                    # Ensure stream_tokens is set for streaming endpoints to enable token-by-token response.
                    if stream and isinstance(request.json, dict):
                        request_data = request.json.copy()
                        request_data['stream_tokens'] = True
                        kwargs['json'] = request_data
                    else:
                        kwargs['json'] = request.json
                elif request.data:
                    kwargs['data'] = request.data

            # Set stream=True for streaming requests to handle chunked responses.
            if stream:
                kwargs['stream'] = True

            response = requests.request(method=request.method, url=target_url, **kwargs)
            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")

        # Ensure response exists before proceeding with any processing.
        if response is None:
            logger.error("Response is None, cannot proceed")
            return jsonify({"error": "Failed to get response from target API"}), 500

        logger.debug(f"Response status: {response.status_code}")
        
        # Handle empty responses gracefully.
        if not response.content and not stream:
            return '', response.status_code

        if stream:
            
            def generate():
                logger.info("Starting stream generator")
                
                # Track message chunks to reconstruct complete messages.
                tool_call_buffer = ""
                capturing_tool_call = False
                
                # Initialize message accumulation variables for both reasoning and assistant messages.
                message_seen = False
                accumulated_json = ""
                
                try:
                    for chunk in response.iter_content():
                        if chunk:
                            # Log raw chunk for all chunks.
                            try:
                                chunk_str = chunk.decode('utf-8')
                                logger.debug(f"Raw chunk: {chunk_str!r}")
                                
                                # Start capturing if we detect function call indicators in the response.
                                if any(keyword in chunk_str for keyword in ['tool_calls', 'function', 'send_message']):
                                    capturing_tool_call = True
                                    tool_call_buffer += chunk_str
                                    logger.info("Started capturing tool call message")
                                # Continue capturing if we're still processing a tool call message.
                                elif capturing_tool_call:
                                    tool_call_buffer += chunk_str
                                
                                # After receiving a complete message or end indicator, log the full captured message.
                                if capturing_tool_call and ('"}' in chunk_str or '"message"' in chunk_str):
                                    logger.info(f"COMPLETE MESSAGE CAPTURE: {tool_call_buffer}")
                            except Exception as e:
                                logger.error(f"Error decoding chunk: {e}")
                            
                            # Process message extraction using multiple pattern matching strategies.
                            try:
                                chunk_str = chunk.decode('utf-8')
                                
                                # Log message format for all chunks to understand structure.
                                if 'function' in chunk_str or 'tool_call' in chunk_str:
                                    logger.info(f"Found potential function call: {chunk_str}")
                                    
                                # Method 1: Direct string search for message patterns.
                                if '"message":' in chunk_str:
                                    logger.info("Found message field in chunk")
                                    message_seen = True
                                    accumulated_json += chunk_str
                                    
                                    # Try to extract the complete message using regex.
                                    import re
                                    message_match = re.search(r'"message":\s*"(.*?)(?<!\\)"', accumulated_json)
                                    if message_match:
                                        message_content = message_match.group(1).replace('\\"', '"')
                                        logger.info(f"Extracted message content: {message_content}")
                                        
                                        # Create and send an assistant message.
                                        assistant_msg = {
                                            "message_type": "assistant_message",
                                            "content": message_content,
                                            "id": "msg_" + str(hash(message_content))
                                        }
                                        message_event = f"data: {json.dumps(assistant_msg)}\n\n"
                                        logger.info(f"Sending assistant message: {message_event}")
                                        yield message_event.encode('utf-8')
                                        
                                        # Skip forwarding the raw chunk.
                                        message_seen = False
                                        accumulated_json = ""
                                        continue
                                
                                # Method 2: Parse complete JSON when message field is detected.
                                elif message_seen and accumulated_json:
                                    accumulated_json += chunk_str
                                    try:
                                        if 'data:' in accumulated_json:
                                            # Try to parse everything after 'data: '.
                                            json_part = accumulated_json.split('data: ', 1)[1].strip()
                                            data = json.loads(json_part)
                                            
                                            # Check for tool_calls structure.
                                            if 'tool_calls' in data and len(data['tool_calls']) > 0:
                                                tool_call = data['tool_calls'][0]
                                                if 'function' in tool_call and 'arguments' in tool_call['function']:
                                                    args_str = tool_call['function']['arguments']
                                                    args = json.loads(args_str)
                                                    
                                                    if 'message' in args:
                                                        message_content = args['message']
                                                        logger.info(f"Successfully extracted message from arguments: {message_content}")
                                                        
                                                        assistant_msg = {
                                                            "message_type": "assistant_message",
                                                            "content": message_content,
                                                            "id": data.get('id', f"msg_{hash(message_content)}")
                                                        }
                                                        
                                                        message_event = f"data: {json.dumps(assistant_msg)}\n\n"
                                                        logger.info(f"Sending complete assistant message: {message_event}")
                                                        yield message_event.encode('utf-8')
                                                        
                                                        # Clear state and skip forwarding this chunk.
                                                        message_seen = False
                                                        accumulated_json = ""
                                                        continue
                                    except json.JSONDecodeError:
                                        # Not complete JSON yet, continue accumulating.
                                        pass
                                    except Exception as e:
                                        logger.error(f"Error processing accumulated JSON: {e}")
                                        # Reset state but continue processing.
                                        message_seen = False
                                        accumulated_json = ""
                                
                                # Method 3: Raw string search for complete message patterns in single chunks.
                                if '"function"' in chunk_str and '"arguments"' in chunk_str and '"message"' in chunk_str:
                                    try:
                                        # This is a more aggressive direct extraction.
                                        import re
                                        direct_message_match = re.search(r'"message":\s*"(.*?)(?<!\\)"\s*,\s*"request_heartbeat"', chunk_str)
                                        if direct_message_match:
                                            message_content = direct_message_match.group(1).replace('\\"', '"')
                                            logger.info(f"Direct extraction of message: {message_content}")
                                            
                                            assistant_msg = {
                                                "message_type": "assistant_message",
                                                "content": message_content,
                                                "id": f"msg_{hash(message_content)}"
                                            }
                                            
                                            message_event = f"data: {json.dumps(assistant_msg)}\n\n"
                                            logger.info(f"Sending directly extracted message: {message_event}")
                                            yield message_event.encode('utf-8')
                                            
                                            # Skip forwarding this chunk.
                                            continue
                                    except Exception as e:
                                        logger.error(f"Error with direct message extraction: {e}")
                            except Exception as e:
                                logger.error(f"Error processing chunk: {e}")
                            
                            # If no extraction methods worked, forward the original chunk unchanged.
                            yield chunk
                        
                    # End of stream - process any remaining accumulated message data.
                    if message_seen and accumulated_json:
                        try:
                            # One last attempt to extract the message.
                            import re
                            final_match = re.search(r'"message":\s*"(.*?)(?<!\\)"', accumulated_json)
                            if final_match:
                                message_content = final_match.group(1).replace('\\"', '"')
                                logger.info(f"Final extraction of message: {message_content}")
                                
                                assistant_msg = {
                                    "message_type": "assistant_message",
                                    "content": message_content,
                                    "id": f"msg_final_{hash(message_content)}"
                                }
                                
                                message_event = f"data: {json.dumps(assistant_msg)}\n\n"
                                logger.info(f"Sending final extracted message: {message_event}")
                                yield message_event.encode('utf-8')
                        except Exception as e:
                            logger.error(f"Error with final message extraction: {e}")
                            
                    logger.info("Stream complete")
                    
                except Exception as e:
                    logger.exception("Stream error")
                    error_msg = f"data: {{\"message_type\":\"error\",\"content\":\"Stream error: {str(e)}\"}}\n\n"
                    yield error_msg.encode('utf-8')
                    yield "data: [DONE]\n\n".encode('utf-8')

            # Set headers for Server-Sent Events streaming response.
            headers = {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache, no-transform',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'
            }

            logger.info("Returning streaming response")
            return Response(
                stream_with_context(generate()),
                status=response.status_code,
                headers=headers,
                direct_passthrough=True
            )

        # Handle empty responses since DELETE sometimes have those.
        if not response.content:
            return '', response.status_code

        # Handle normal (non-streaming) responses.
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

@app.route('/refresh-tokens', methods=['GET'])
def refresh_tokens():
    """
    Refresh tokens from the database and reload them into memory.

    Returns:
        dict: A JSON response indicating the success or failure of the operation.
    """
    # Client IP must be from 127.0.0.1
    if request.remote_addr != '127.0.0.1':
        return jsonify({"error": "Unauthorized: Invalid client IP"}), 401

    try:
        load_tokens_into_memory()
        logger.info("Tokens reloaded from the database.")
        return jsonify({"status": "success", "message": "Tokens reloaded successfully"})
    except Exception as e:
        logger.error(f"Error refreshing tokens: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':

    with app.app_context():
        set_target(API_BASE_URL)
    
    logger.info(f"Starting proxy server on port {args.port}")
    logger.info(f"Proxying requests to: {API_BASE_URL}")
    app.run(host='0.0.0.0', port=args.port, debug=args.debug)
