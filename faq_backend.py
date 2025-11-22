import os
import json
import uuid
import time
import logging
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
app = Flask(__name__)

# CORS - Configure properly for production
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*').split(',')
CORS(app, origins=ALLOWED_ORIGINS)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour", "50 per minute"],
    storage_uri=os.getenv('REDIS_URL', 'memory://')
)

# Environment variables with validation
FAQ_SERVICE_URL = os.getenv('FAQ_SERVICE_URL', 'http://localhost:9008')
TOKEN_EXPIRY_HOURS = float(os.getenv('TOKEN_EXPIRY_HOURS', 1.0))
FAQ_SERVICE_TIMEOUT = int(os.getenv('FAQ_SERVICE_TIMEOUT', 30))
DEBUG_MODE = os.getenv('DEBUG_MODE', 'False').lower() == 'true'
PORT = int(os.getenv('PORT', 3001))
HOST = os.getenv('HOST', '0.0.0.0')

# Limits
MAX_MESSAGES = int(os.getenv('MAX_MESSAGES', 50))
MAX_MESSAGE_LENGTH = int(os.getenv('MAX_MESSAGE_LENGTH', 5000))

# Redis configuration
USE_REDIS = os.getenv('USE_REDIS', 'True').lower() == 'true'
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Setup structured logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Redis with connection pooling
redis_client = None
if USE_REDIS:
    try:
        import redis
        redis_client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            health_check_interval=30
        )
        redis_client.ping()
        logger.info(f"Connected to Redis at {REDIS_URL}")
    except ImportError:
        logger.warning("redis module not installed. Install with: pip install redis")
        USE_REDIS = False
        redis_client = None
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        USE_REDIS = False
        redis_client = None

# Fallback in-memory storage (not recommended for production)
requests_store = {}

class TokenStore:
    """Unified interface for token storage with Redis support"""
    
    def __init__(self):
        self.use_redis = USE_REDIS and redis_client is not None
        if not self.use_redis:
            logger.warning("Using in-memory storage - data will be lost on restart!")
    
    def set(self, token, data):
        """Store token data with expiration"""
        if self.use_redis:
            try:
                expiry_seconds = int(TOKEN_EXPIRY_HOURS * 3600)
                redis_client.setex(
                    f"token:{token}",
                    expiry_seconds,
                    json.dumps(data)
                )
                return True
            except Exception as e:
                logger.error(f"Redis set error: {e}")
                return False
        else:
            requests_store[token] = {**data, 'expiry': time.time() + (TOKEN_EXPIRY_HOURS * 3600)}
            return True
    
    def get(self, token):
        """Retrieve token data"""
        if self.use_redis:
            try:
                data = redis_client.get(f"token:{token}")
                return json.loads(data) if data else None
            except Exception as e:
                logger.error(f"Redis get error: {e}")
                return None
        else:
            data = requests_store.get(token)
            if data and time.time() < data.get('expiry', 0):
                return data
            elif data:
                del requests_store[token]
            return None
    
    def exists(self, token):
        """Check if token exists and is valid"""
        return self.get(token) is not None
    
    def delete(self, token):
        """Delete token"""
        if self.use_redis:
            try:
                redis_client.delete(f"token:{token}")
            except Exception as e:
                logger.error(f"Redis delete error: {e}")
        else:
            requests_store.pop(token, None)

token_store = TokenStore()

# Request validation decorator
def validate_request_json(*required_fields):
    """Decorator to validate JSON request and required fields"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                logger.warning(f"Non-JSON request to {request.path}")
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            # Check content length
            if request.content_length and request.content_length > 1024 * 1024:  # 1MB limit
                return jsonify({'error': 'Request too large'}), 413
            
            data = request.get_json()
            
            for field in required_fields:
                if field not in data:
                    logger.warning(f"Missing field: {field}")
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/request', methods=['POST'])
@limiter.limit("20 per minute")
@validate_request_json('messages')
def request_endpoint():
    """
    Accept chat history and return a token.
    
    POST /request
    {
        "messages": [
            {"role": "system", "content": "..."},
            {"role": "user", "content": "..."}
        ]
    }
    
    Returns: {"token": "...", "expires_in": 3600}
    """
    try:
        data = request.get_json()
        messages = data.get('messages', [])
        
        # Validate messages structure
        if not isinstance(messages, list) or len(messages) == 0:
            return jsonify({'error': 'Messages must be a non-empty list'}), 400
        
        if len(messages) > MAX_MESSAGES:
            return jsonify({'error': f'Too many messages (max: {MAX_MESSAGES})'}), 400
        
        # Validate each message
        for idx, msg in enumerate(messages):
            if not isinstance(msg, dict):
                return jsonify({'error': f'Message {idx} must be an object'}), 400
            if 'role' not in msg or 'content' not in msg:
                return jsonify({'error': f'Message {idx} missing role or content'}), 400
            if len(msg['content']) > MAX_MESSAGE_LENGTH:
                return jsonify({'error': f'Message {idx} exceeds max length'}), 400
        
        # Generate secure token
        token = f"token_{uuid.uuid4().hex}_{int(time.time() * 1000)}"
        
        # Store with metadata
        token_data = {
            'messages': messages,
            'created_at': time.time(),
            'ip': request.remote_addr
        }
        
        if not token_store.set(token, token_data):
            logger.error("Failed to store token")
            return jsonify({'error': 'Failed to create session'}), 500
        
        logger.info(f"Token created: {len(messages)} messages from {request.remote_addr}")
        
        return jsonify({
            'token': token,
            'expires_in': int(TOKEN_EXPIRY_HOURS * 3600)
        }), 200
    
    except Exception as e:
        logger.error(f"Error in /request: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/chat', methods=['POST'])
@limiter.limit("30 per minute")
@validate_request_json('token')
def chat_endpoint():
    """
    Forward question to FAQ service and stream response.
    
    POST /chat
    {"token": "token_..."}
    
    Returns: Server-Sent Events stream
    """
    try:
        data = request.get_json()
        token = data.get('token', '').strip()
        
        if not token:
            return jsonify({'error': 'Token required'}), 400
        
        # Retrieve and validate token
        stored_data = token_store.get(token)
        if not stored_data:
            logger.warning(f"Invalid/expired token: {token[:20]}...")
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        messages = stored_data.get('messages', [])
        
        # Extract last user message
        last_user_message = None
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get('role') == 'user':
                content = msg.get('content', '').strip()
                if content:
                    last_user_message = content
                    break
        
        if not last_user_message:
            return jsonify({'error': 'No question found in messages'}), 400
        
        logger.info(f"Processing question (token: {token[:16]}...)")
        
        # Call FAQ service
        faq_answer = "Service temporarily unavailable. Please try again."
        try:
            response = requests.post(
                FAQ_SERVICE_URL,
                json={'question': last_user_message},
                timeout=FAQ_SERVICE_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            faq_data = response.json()
            faq_answer = faq_data.get('answer', '').strip() or faq_answer
            
        except requests.exceptions.Timeout:
            logger.error(f"FAQ service timeout")
        except requests.exceptions.RequestException as e:
            logger.error(f"FAQ service error: {str(e)}")
        except ValueError:
            logger.error("Invalid JSON from FAQ service")
        
        # Stream response
        def generate():
            words = faq_answer.split(' ')
            for i, word in enumerate(words):
                token_str = word + (' ' if i < len(words) - 1 else '')
                yield f"data: {json.dumps({'token': token_str})}\n\n"
            logger.info(f"Stream completed for {token[:16]}...")
        
        return Response(
            generate(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no'
            }
        )
    
    except Exception as e:
        logger.error(f"Error in /chat: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    faq_status = 'unknown'
    try:
        resp = requests.get(f"{FAQ_SERVICE_URL}/health", timeout=2)
        faq_status = 'healthy' if resp.status_code == 200 else 'unhealthy'
    except:
        faq_status = 'unavailable'
    
    return jsonify({
        'status': 'healthy',
        'service': 'FAQ Bot Backend',
        'timestamp': datetime.utcnow().isoformat(),
        'storage': 'redis' if token_store.use_redis else 'memory',
        'faq_service_status': faq_status
    }), 200


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429


@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.warning("=" * 60)
    logger.warning("Using Flask development server - NOT for production!")
    logger.warning("Use: gunicorn app:app --bind 0.0.0.0:3001 --workers 4")
    logger.warning("=" * 60)
    app.run(host=HOST, port=PORT, debug=DEBUG_MODE)