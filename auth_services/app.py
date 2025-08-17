from flask import Flask, jsonify, request
import jwt
from flask_cors import CORS
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from io import BytesIO
import base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
import os
import time

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get('SECRET_KEY', 'QHZ/5n4Y+AugECPP12uVY/9mWZ14nqEfdiBB8Jo6//g')
client = MongoClient(os.environ.get('MONGO_URI', 'mongodb+srv://2023171002:1234@cluster0.rquhrnu.mongodb.net/auth_db?retryWrites=true&w=majority&appName=Cluster0'))
db = client['auth_db']
users_collection = db['users']
logs_collection = db['auth_logs']  # Collection for logs

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    storage_uri="memory://"
)

def init_db():
    users = [
        {"username": "user1", "password": generate_password_hash("pass1"), "two_factor_secret": None, "two_factor_enabled": False},
        {"username": "user2", "password": generate_password_hash("pass2"), "two_factor_secret": None, "two_factor_enabled": False}
    ]
    for user in users:
        if not users_collection.find_one({"username": user["username"]}):
            users_collection.insert_one(user)
    logs_collection.create_index([("timestamp", -1)])  # Index for sorting logs by timestamp

def log_action(user, route, method, status, message, response_time=None):
    """Log an action to the auth_logs collection, consistent with task_services."""
    log_entry = {
        "user": user or "anonymous",
        "route": route,
        "method": method,
        "status": status,
        "response_time": response_time if response_time is not None else 0,  # Default to 0 if not provided
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "message": message,
        "service": "auth"  # Add service field for DashLogsComponent
    }
    logs_collection.insert_one(log_entry)

@app.before_request
def log_request():
    """Middleware to log each HTTP request, excluding /logs endpoint."""
    if request.endpoint != 'get_logs':
        request.start_time = time.time()  # Record start time for response_time calculation

@app.after_request
def update_log_status(response):
    """Update log with response status and response time after request."""
    if request.endpoint != 'get_logs':
        response_time = (time.time() - request.start_time) * 1000  # Convert to milliseconds
        logs_collection.update_one(
            {"route": request.path, "timestamp": {"$gte": datetime.datetime.now(datetime.timezone.utc).isoformat()}},
            {"$set": {"status": response.status_code, "response_time": response_time}}
        )
    return response

@app.route('/register', methods=['POST'])
@limiter.limit("100 per minute")
def register():
    start_time = time.time()  # Start time for response_time
    data = request.get_json()
    required_fields = ['username', 'password']
    if not all(field in data for field in required_fields):
        log_action(None, '/register', request.method, 400, "Todos los campos son requeridos", (time.time() - start_time) * 1000)
        return jsonify({"statusCode": 400, "intData": {"message": "Todos los campos son requeridos", "data": None}})

    username = data['username']
    password = data['password']

    if users_collection.find_one({"username": username}):
        log_action(username, '/register', request.method, 400, "Nombre de usuario ya registrado", (time.time() - start_time) * 1000)
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

    log_action(username, '/register', request.method, 201, "Usuario registrado exitosamente", (time.time() - start_time) * 1000)
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
    start_time = time.time()
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    otp = data.get('otp')

    if not username or not password or not otp:
        log_action(username or "anonymous", '/login', request.method, 400, "Usuario, contraseña y código OTP son requeridos", (time.time() - start_time) * 1000)
        return jsonify({"statusCode": 400, "intData": {"message": "Usuario, contraseña y código OTP son requeridos", "data": None}})

    user = users_collection.find_one({"username": username})
    if not user or not check_password_hash(user["password"], password):
        log_action(username or "anonymous", '/login', request.method, 401, "Credenciales incorrectas", (time.time() - start_time) * 1000)
        return jsonify({"statusCode": 401, "intData": {"message": "Credenciales incorrectas", "data": None}})

    if user.get("two_factor_enabled", False):
        totp = pyotp.TOTP(user["two_factor_secret"])
        if not totp.verify(otp, valid_window=1):
            log_action(username, '/login', request.method, 401, "Código OTP inválido", (time.time() - start_time) * 1000)
            return jsonify({"statusCode": 401, "intData": {"message": "Código OTP inválido", "data": None}})

    payload = {
        'user_id': str(user["_id"]),
        'username': user["username"],
        'permission': 'admin',
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    log_action(username, '/login', request.method, 200, "Login exitoso", (time.time() - start_time) * 1000)
    return jsonify({"statusCode": 200, "intData": {"message": "Login exitoso", "token": token}})

@app.route('/logs', methods=['GET'])
@limiter.limit("100 per minute")
def get_logs():
    """Retrieve logs from MongoDB with optional filters."""
    start_time = time.time()
    try:
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
            try:
                query['status'] = int(status)
            except ValueError:
                log_action(request.args.get('user') or "anonymous", '/logs', request.method, 400, "El status debe ser un número entero", (time.time() - start_time) * 1000)
                return jsonify({
                    "statusCode": 400,
                    "intData": {"message": "El status debe ser un número entero", "data": None}
                })
        if start_date and end_date:
            try:
                query['timestamp'] = {
                    "$gte": datetime.datetime.fromisoformat(start_date).isoformat(),
                    "$lte": datetime.datetime.fromisoformat(end_date).isoformat()
                }
            except ValueError:
                log_action(request.args.get('user') or "anonymous", '/logs', request.method, 400, "Formato de fecha inválido (ISO format)", (time.time() - start_time) * 1000)
                return jsonify({
                    "statusCode": 400,
                    "intData": {"message": "Formato de fecha inválido (ISO format)", "data": None}
                })

        logs = list(logs_collection.find(query).sort("timestamp", -1))
        for log in logs:
            log['id'] = str(log['_id'])  # Convert ObjectId to string for JSON
            log.pop('_id', None)
            log['service'] = 'auth'  # Ensure service field is included

        log_action(request.args.get('user') or "anonymous", '/logs', request.method, 200, "Logs recuperados exitosamente", (time.time() - start_time) * 1000)
        return jsonify({
            "statusCode": 200,
            "intData": {
                "message": "Logs recuperados exitosamente",
                "data": logs
            }
        })
    except Exception as e:
        log_action(request.args.get('user') or "anonymous", '/logs', request.method, 500, f"Error al recuperar logs: {str(e)}", (time.time() - start_time) * 1000)
        return jsonify({
            "statusCode": 500,
            "intData": {
                "message": "Error al recuperar los logs",
                "error": str(e)
            }
        })

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)