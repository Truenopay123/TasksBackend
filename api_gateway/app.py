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
import traceback

# =========================
# Configuración Flask
# =========================
app = Flask(__name__)
CORS(app, resources={r"/logs": {"origins": "https://tasks-seguridad.vercel.app"}})  # Especifica orígenes permitidos

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
REDIS_URI = os.environ.get('REDIS_URI')  # Requerido para producción; configura en Render

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
# Configuración Rate Limiter
# =========================
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per hour"],  # Límite global conservador
    storage_uri=REDIS_URI if REDIS_URI else "memory://"  # Usa Redis si está configurado, sino memoria
)

# =========================
# Conexión diferida a MongoDB
# =========================
client = None
db = None
logs_collection = None
bans_collection = None  # Nueva colección para bans

def init_db():
    global client, db, logs_collection, bans_collection
    try:
        client = MongoClient(
            MONGO_URI,
            tls=True,
            tlsAllowInvalidCertificates=False
        )
        db = client['gateway_db']
        logs_collection = db['logs']
        bans_collection = db['bans']  # Nueva colección para IPs bloqueadas
        logs_collection.create_index("timestamp")
        print("[OK] Conectado a MongoDB Atlas")
        logger.info("[OK] Conectado a MongoDB Atlas")
    except Exception as e:
        print(f"[Error] No se pudo conectar a MongoDB: {e}")
        logger.error(f"[Error] No se pudo conectar a MongoDB: {e}")

# Inicializamos DB al iniciar el servidor
init_db()

# =========================
# Manejador de errores Rate Limit
# =========================
@app.errorhandler(RateLimitExceeded)
def rate_limit_exceeded(e):
    route_limits = {
        '/auth/': '50 peticiones por segundo',  # Reducido temporalmente para pruebas
        '/user/': '50 peticiones por segundo',
        '/task/': '50 peticiones por segundo',
        '/logs': '50 peticiones por segundo'
    }
    default_limits = '500 peticiones por hora'
    route = request.path.split('/')[1] + '/' if request.path.startswith(('/auth/', '/user/', '/task/', '/logs')) else None
    limit_message = route_limits.get(route, default_limits)

    response = jsonify({
        'error': 'Límite de peticiones excedido',
        'message': f'Has alcanzado el límite de peticiones: {limit_message}. Por favor, intenta de nuevo más tarde.',
        'statusCode': 429
    })
    response.status_code = 429
    return response

# =========================
# Verificación de bans antes de cada request
# =========================
@app.before_request
def check_banned():
    ip = get_remote_address()
    if bans_collection and bans_collection.find_one({'ip': ip}):
        return jsonify({'error': 'IP bloqueada por abuso'}), 403
    request.start_time = time.time()

# =========================
# Logging de requests
# =========================
def log_request(response):
    if logs_collection is None:
        init_db()  # Reintenta conexión si es necesario
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
        'user': user,
        'ip': get_remote_address()  # Agregado para rastreo de IPs
    }
    try:
        logs_collection.insert_one(log_entry)
    except Exception as e:
        logger.error(f"Error guardando log en MongoDB: {e}\n{traceback.format_exc()}")

    log_message = (
        f"Route: {request.path} "
        f"Service: {service} "
        f"Method: {request.method} "
        f"Status: {response.status_code} "
        f"response_time: {duration:.2f}s "
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
        f"User: {user} "
        f"IP: {log_entry['ip']}"
    )
    if 200 <= response.status_code < 300:
        logger.info(log_message)
    elif 400 <= response.status_code < 500:
        logger.warning(log_message)
    else:
        logger.error(log_message)

# Middleware para logear solicitudes y respuestas
@app.after_request
def after_request(response):
    log_request(response)
    return response

# =========================
# Rutas
# =========================
@app.route('/logs', methods=['GET'])
@limiter.limit("50 per second")  # Reducido temporalmente
def get_logs():
    """Recupera los logs de MongoDB con filtros opcionales."""
    try:
        if logs_collection is None:
            init_db()
            if logs_collection is None:
                raise Exception("No se pudo conectar a MongoDB después de reintento")

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
            query['status'] = int(status)
        if start_date and end_date:
            query['timestamp'] = {"$gte": start_date, "$lte": end_date}

        logger.info("Solicitud GET a /logs con query: %s", query)

        logs = list(logs_collection.find(query).sort("timestamp", -1))
        for log in logs:
            log['_id'] = str(log['_id'])

        logger.info("Logs recuperados: %d documentos", len(logs))

        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Logs recuperados exitosamente",
                "data": logs
            }
        })
    except Exception as e:
        logger.error("Error en get_logs: %s\n%s", str(e), traceback.format_exc())
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": "Error al recuperar los logs",
                "error": str(e)
            }
        })

@app.route('/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@limiter.limit("50 per second")  # Reducido temporalmente
def proxy_auth(path):
    method = request.method
    url = f'{AUTH_SERVICE_URL}/{path}'
    try:
        resp = requests.request(
            method=method,
            url=url,
            json=request.get_json(silent=True),
            headers={key: value for key, value in request.headers if key.lower() != 'host'},
            timeout=5  # Agregado para evitar bloqueos
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        logger.error("Error en proxy_auth: %s\n%s", str(e), traceback.format_exc())
        return jsonify({"error": "Error interno en el servicio de autenticación"}), 500

@app.route('/user/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@limiter.limit("50 per second")  # Reducido temporalmente
def proxy_user(path):
    method = request.method
    url = f'{USER_SERVICE_URL}/{path}'
    try:
        resp = requests.request(
            method=method,
            url=url,
            json=request.get_json(silent=True),
            headers={key: value for key, value in request.headers if key.lower() != 'host'},
            timeout=5  # Agregado para evitar bloqueos
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        logger.error("Error en proxy_user: %s\n%s", str(e), traceback.format_exc())
        return jsonify({"error": "Error interno en el servicio de usuario"}), 500

@app.route('/task/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@limiter.limit("50 per second")  # Reducido temporalmente
def proxy_task(path):
    method = request.method
    url = f'{TASK_SERVICE_URL}/{path}'
    try:
        resp = requests.request(
            method=method,
            url=url,
            json=request.get_json(silent=True),
            headers={key: value for key, value in request.headers if key.lower() != 'host'},
            timeout=5  # Agregado para evitar bloqueos
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        logger.error("Error en proxy_task: %s\n%s", str(e), traceback.format_exc())
        return jsonify({"error": "Error interno en el servicio de tareas"}), 500

# =========================
# Arranque de la app
# =========================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Escuchando en el puerto {port}")
    app.run(host='0.0.0.0', port=port, debug=False)  # Debug=False para producción