import os
import time
import logging
import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from datetime import datetime
import pyotp
import qrcode
from io import BytesIO
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Configuración Flask
app = Flask(__name__)
CORS(app)

# Variables de entorno
SECRET_KEY = os.environ.get('SECRET_KEY', 'QHZ/5n4Y+AugECPP12uVY/9mWZ14nqEfdiBB8Jo6//g')
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb+srv://2023171002:1234@cluster0.rquhrnu.mongodb.net/auth_db?retryWrites=true&w=majority&appName=Cluster0')
REDIS_URL = os.environ.get('REDIS_URL', 'redis://red-d2gm9ibuibrs73eft4l0:6379')

# Configuración del logger
logging.basicConfig(
    filename='auth_service.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('auth_service_logger')

# Conexión a MongoDB
client = MongoClient(MONGO_URI)
db = client['auth_db']
users_collection = db['users']
auth_logs_collection = db['auth_logs']

# Configuración Rate Limiter con Redis
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per second", "100 per minute"],  # Límite global: 1000 req/s, mantener 100/min
    storage_uri=REDIS_URL
)

# Decorador de autenticación
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'statusCode': 401, 'intData': {'message': 'Token requerido', 'data': None}}), 401
        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if decoded.get('permission') != 'admin':
                return jsonify({'statusCode': 403, 'intData': {'message': 'Permiso de admin requerido', 'data': None}}), 403
            request.user = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({'statusCode': 401, 'intData': {'message': 'Token expirado', 'data': None}}), 401
        except jwt.InvalidTokenError:
            return jupytext({'statusCode': 401, 'intData': {'message': 'Token inválido', 'data': None}}), 401
        return f(*args, **kwargs)
    return decorated

# Manejador de errores Rate Limit
@app.errorhandler(RateLimitExceeded)
def rate_limit_exceeded(e):
    route_limits = {
        '/register': '100 peticiones por minuto',
        '/login': '100 peticiones por minuto',
        '/logs': '30 peticiones por minuto',
        '/': '1000 peticiones por segundo'
    }
    default_limits = '1000 peticiones por segundo o 100 peticiones por minuto'
    route = request.path if request.path in route_limits else '/'
    limit_message = route_limits.get(route, default_limits)

    log_message = (
        f"Rate limit excedido: {limit_message} "
        f"Route: {request.path} "
        f"IP: {get_remote_address()} "
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    logger.warning(log_message)

    response = jsonify({
        'statusCode': 429,
        'intData': {
            'message': f'Has alcanzado el límite de peticiones: {limit_message}. Por favor, intenta de nuevo más tarde.',
            'data': None
        }
    })
    response.status_code = 429
    return response

# Logging de requests
def log_request(response):
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

    log_message = {
        'route': request.path,
        'service': 'auth_service',
        'method': request.method,
        'status': response.status_code,
        'response_time': duration,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': user
    }
    auth_logs_collection.insert_one(log_message)

    log_file_message = (
        f"Route: {request.path} "
        f"Method: {request.method} "
        f"Status: {response.status_code} "
        f"response_time: {duration:.2f}s "
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
        f"User: {user}"
    )
    if 200 <= response.status_code < 300:
        logger.info(log_file_message)
    elif 400 <= response.status_code < 500:
        logger.warning(log_file_message)
    else:
        logger.error(log_file_message)

@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    log_request(response)
    return response

# Inicialización de la base de datos
def init_db():
    users = [
        {"username": "user1", "password": generate_password_hash("pass1"), "two_factor_secret": None, "two_factor_enabled": False},
        {"username": "user2", "password": generate_password_hash("pass2"), "two_factor_secret": None, "two_factor_enabled": False}
    ]
    for user in users:
        if not users_collection.find_one({"username": user["username"]}):
            users_collection.insert_one(user)

# Rutas
@app.route('/register', methods=['POST'])
@limiter.limit("100 per minute")
def register():
    data = request.get_json()
    required_fields = ['username', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({"statusCode": 400, "intData": {"message": "Todos los campos son requeridos", "data": None}})

    username = data['username']
    password = data['password']

    if users_collection.find_one({"username": username}):
        return jsonify({"statusCode": 400, "intData": {"message": "Nombre de usuario ya registrado", "data": None}})

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name='TuApp')

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode('utf-8')

    hashed_password = generate_password_hash(password)
    user = {
        "username": username,
        "password": hashed_password,
        "two_factor_secret": secret,
        "two_factor_enabled": True
    }
    users_collection.insert_one(user)

    return jsonify({
        "statusCode": 201,
        "intData": {
            "message": "Usuario registrado exitosamente. Escanea el código QR con tu app de autenticación.",
            "data": {"qr_code": f"data:image/png;base64,{qr_code}", "secret": secret}
        }
    })

@app.route('/login', methods=['POST'])
@limiter.limit("100 per minute")
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    otp = data.get('otp')

    if not username or not password or not otp:
        return jsonify({"statusCode": 400, "intData": {"message": "Usuario, contraseña y código OTP son requeridos", "data": None}})

    user = users_collection.find_one({"username": username})
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"statusCode": 401, "intData": {"message": "Credenciales incorrectas", "data": None}})

    if user.get("two_factor_enabled", False):
        totp = pyotp.TOTP(user["two_factor_secret"])
        if not totp.verify(otp, valid_window=1):
            return jsonify({"statusCode": 401, "intData": {"message": "Código OTP inválido", "data": None}})

    payload = {
        'user_id': str(user["_id"]),
        'username': user["username"],
        'permission': 'admin',
        'exp': datetime.utcnow() + datetime.timedelta(minutes=5)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    return jsonify({"statusCode": 200, "intData": {"message": "Login exitoso", "token": token}})

@app.route('/logs', methods=['GET'])
@limiter.limit("30 per minute")
@token_required
def get_logs():
    logs = list(auth_logs_collection.find().sort("timestamp", -1))
    logs_list = [{"id": str(log["_id"]), **{k: v for k, v in log.items() if k != "_id"}} for log in logs]
    return jsonify({"statusCode": 200, "intData": {"message": "Logs recuperados con éxito", "data": logs_list}})

# Arranque de la app
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)