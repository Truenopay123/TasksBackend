import os
import time
import logging
import jwt
import requests
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from pymongo import MongoClient, DESCENDING
from bson import ObjectId
import pytz
import ssl

# =========================
# Configuración Flask
# =========================
app = Flask(__name__)
CORS(app)

# =========================
# Variables de entorno
# =========================
MONGO_URI = os.environ.get(
    'MONGO_URI',
    "mongodb+srv://2023171002:1234@cluster0.rquhrnu.mongodb.net/gateway_db?retryWrites=true&w=majority&tls=true"
)
AUTH_SERVICE_URL = os.environ.get('AUTH_SERVICE_URL', "https://auth-services-ja81.onrender.com")
USER_SERVICE_URL = os.environ.get('USER_SERVICE_URL', "https://user-services-wwqz.onrender.com")
TASK_SERVICE_URL = os.environ.get('TASK_SERVICE_URL', "https://task-services-vrvc.onrender.com")
SECRET_KEY = os.environ.get('SECRET_KEY', "QHZ/5n4Y+AugECPP12uVY/9mWZ14nqEfdiBB8Jo6//g")
REDIS_URL = os.environ.get('REDIS_URL', "redis://red-d2gm9ibuibrs73eft4l0:6379")  # Redis URL from Render

# =========================
# Configuración del logger
# =========================
logging.basicConfig(
    filename='api.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('api_logger')

# =========================
# Configuración Rate Limiter con Redis
# =========================
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per second", "500 per hour"],  # Límite global: 1000 req/s y 500 req/h
    storage_uri=REDIS_URL  # Usamos Redis como backend de almacenamiento
)

# =========================
# Conexión diferida a MongoDB
# =========================
client = None
db = None
logs_collection = None

def init_db():
    global client, db, logs_collection
    try:
        client = MongoClient(
            MONGO_URI,
            tls=True,
            tlsAllowInvalidCertificates=False
        )
        db = client['gateway_db']
        logs_collection = db['logs']
        logs_collection.create_index("timestamp")
        print("[OK] Conectado a MongoDB Atlas")
    except Exception as e:
        print(f"[Error] No se pudo conectar a MongoDB: {e}")

# Inicializamos DB al iniciar el servidor
init_db()

# =========================
# Manejador de errores Rate Limit
# =========================
@app.errorhandler(RateLimitExceeded)
def rate_limit_exceeded(e):
    route_limits = {
        '/auth/': '100 peticiones por segundo',
        '/user/': '100 peticiones por segundo',
        '/task/': '100 peticiones por segundo',
        '/logs': '100 peticiones por segundo',
        '/': '1000 peticiones por segundo'  # Límite global
    }
    default_limits = '1000 peticiones por segundo o 500 peticiones por hora'
    route = request.path.split('/')[1] + '/' if request.path.startswith(('/auth/', '/user/', '/task/', '/logs')) else '/'
    limit_message = route_limits.get(route, default_limits)

    log_message = (
        f"Rate limit excedido: {limit_message} "
        f"Route: {request.path} "
        f"IP: {get_remote_address()} "
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    logger.warning(log_message)

    # Guardar en MongoDB si logs_collection está disponible
    if logs_collection:
        try:
            logs_collection.insert_one({
                'route': request.path,
                'service': 'rate_limit',
                'method': request.method,
                'status': 429,
                'response_time': 0,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'user': 'anonymous',
                'error': 'Rate limit excedido'
            })
        except Exception as e:
            logger.error(f"Error guardando log de rate limit en MongoDB: {e}")

    response = jsonify({
        'error': 'Límite de peticiones excedido',
        'message': f'Has alcanzado el límite de peticiones: {limit_message}. Por favor, intenta de nuevo más tarde.',
        'statusCode': 429
    })
    response.status_code = 429
    return response

# =========================
# Logging de requests
# =========================
def log_request(response):
    if logs_collection is None:
        return response

    start_time = getattr(request, 'start_time', time.time())
    duration = time.time() - start_time

    user = 'anonymous'
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer '):
        try:
            decoded_token = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
            user = decoded_token.get('username', 'anonymous')
        except jwt.InvalidTokenError:
            user = 'invalid_token'

    service = {
        '/auth/': 'auth_service',
        '/user/': 'user_service',
        '/task/': 'task_service'
    }.get(request.path.split('/')[1] + '/', 'unknown_service')

    log_entry = {
        'route': request.path,
        'service': service,
        'method': request.method,
        'status': response.status_code,
        'response_time': round(duration, 2),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': user
    }
    try:
        logs_collection.insert_one(log_entry)
    except Exception as e:
        logger.error(f"Error guardando log en MongoDB: {e}")

    log_message = (
        f"Route: {request.path} "
        f"Service: {service} "
        f"Method: {request.method} "
        f"Status: {response.status_code} "
        f"response_time: {duration:.2f}s "
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
        f"User: {user}"
    )
    if 200 <= response.status_code < 300:
        logger.info(log_message)
    elif 400 <= response.status_code < 500:
        logger.warning(log_message)
    else:
        logger.error(log_message)

# Middleware para logear solicitudes y respuestas
@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    log_request(response)
    return response

# =========================
# Rutas
# =========================
@app.route('/logs', methods=['GET'])
@limiter.limit("100 per second")
def get_logs():
    """Recupera los logs de MongoDB con filtros opcionales."""
    try:
        # Filtros opcionales desde los parámetros de la solicitud
        user = request.args.get('user')
        route = request.args.get('route')
        status = request.args.get('status')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        query = {}
        if user:
            query['user'] = user
        if route:
            query['route'] = route
        if status:
            query['status'] = int(status)  # Ajusta según el formato de status
        if start_date and end_date:
            query['timestamp'] = {"$gte": start_date, "$lte": end_date}
        
        logs = list(logs_collection.find().sort("timestamp", -1))
        for log in logs:
            log['_id'] = str(log['_id'])  # Convierte ObjectId a string para JSON

        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Logs recuperados exitosamente",
                "data": logs
            }
        })
    except Exception as e:
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": "Error al recuperar los logs",
                "error": str(e)
            }
        })

@app.route('/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@limiter.limit("100 per second")
def proxy_auth(path):
    method = request.method
    url = f'{AUTH_SERVICE_URL}/{path}'
    logger.info(f"Proxying request: {method} {url} with body {request.get_json(silent=True)}")
    try:
        resp = requests.request(
            method=method,
            url=url,
            json=request.get_json(silent=True),
            headers={key: value for key, value in request.headers if key.lower() != 'host'},
            timeout=10
        )
        logger.info(f"Received raw response from {url}: {resp.text}")
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error proxying to {url}: {str(e)}")
        return jsonify({"error": "Error interno al proxyar", "details": str(e)}), 500
    except ValueError as e:
        logger.error(f"Invalid JSON response from {url}: {str(e)} - Raw response: {resp.text}")
        return jsonify({"error": "Error interno al proxyar", "details": str(e)}), 500

@app.route('/user/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@limiter.limit("100 per second")
def proxy_user(path):
    method = request.method
    url = f'{USER_SERVICE_URL}/{path}'
    resp = requests.request(
        method=method,
        url=url,
        json=request.get_json(silent=True),
        headers={key: value for key, value in request.headers if key.lower() != 'host'}
    )
    return jsonify(resp.json()), resp.status_code

@app.route('/task/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@limiter.limit("100 per second")
def proxy_task(path):
    method = request.method
    url = f'{TASK_SERVICE_URL}/{path}'
    resp = requests.request(
        method=method,
        url=url,
        json=request.get_json(silent=True),
        headers={key: value for key, value in request.headers if key.lower() != 'host'}
    )
    return jsonify(resp.json()), resp.status_code

# =========================
# Arranque de la app
# =========================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)