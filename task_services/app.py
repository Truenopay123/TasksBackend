import os
import time
import logging
import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from bson import ObjectId
from werkzeug.security import generate_password_hash
from functools import wraps
from datetime import datetime

# Configuración Flask
app = Flask(__name__)
CORS(app)

# Variables de entorno
SECRET_KEY = os.environ.get('SECRET_KEY', "QHZ/5n4Y+AugECPP12uVY/9mWZ14nqEfdiBB8Jo6//g")
MONGO_URI = os.environ.get('MONGO_URI', "mongodb+srv://2023171002:1234@cluster0.rquhrnu.mongodb.net/tasks_db?retryWrites=true&w=majority&appName=Cluster0")
REDIS_URL = os.environ.get('REDIS_URL', "redis://red-d2gm9ibuibrs73eft4l0:6379")

# Configuración del logger
logging.basicConfig(
    filename='task_service.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('task_service_logger')

# Conexión a MongoDB
client = MongoClient(MONGO_URI)
db = client['tasks_db']
tasks_collection = db['tasks']
users_collection = db['users']
task_logs_collection = db['task_logs']

# Crear índices para evitar duplicados
tasks_collection.create_index("name", unique=True)
users_collection.create_index("username", unique=True)

# Configuración Rate Limiter con Redis
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per second", "200 per day", "50 per hour"],  # Límite global: 1000 req/s
    storage_uri=REDIS_URL
)

# Manejador de errores Rate Limit
@app.errorhandler(RateLimitExceeded)
def rate_limit_exceeded(e):
    route_limits = {
        '/tasks': '30 peticiones por minuto',
        '/id_tasks/': '30 peticiones por minuto',
        '/Usertasks/': '30 peticiones por minuto',
        '/register_task': '30 peticiones por minuto',
        '/update_task/': '30 peticiones por minuto',
        '/delete_task/': '30 peticiones por minuto',
        '/disable_task/': '30 peticiones por minuto',
        '/enable_task/': '30 peticiones por minuto',
        '/update_task_status/': '30 peticiones por minuto',
        '/logs': '30 peticiones por minuto',
        '/': '1000 peticiones por segundo'
    }
    default_limits = '1000 peticiones por segundo, 200 peticiones por día o 50 peticiones por hora'
    route = request.path if request.path in route_limits else request.path.split('/')[1] + '/' if request.path.startswith(tuple(route_limits.keys())) else '/'
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
        'service': 'task_service',
        'method': request.method,
        'status': response.status_code,
        'response_time': duration,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': user
    }
    task_logs_collection.insert_one(log_message)

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

# Validaciones y datos iniciales
VALID_STATUSES = ['InProgress', 'Revision', 'Completed', 'Paused', 'Incomplete']

def validate_date(date_str: str) -> bool:
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def init_db():
    users = [
        {"username": "username1", "password": generate_password_hash("Hola.123"), "status": 1, "two_factor_enabled": False},
        {"username": "username2", "password": generate_password_hash("Hola.123"), "status": 1, "two_factor_enabled": False},
        {"username": "username3", "password": generate_password_hash("Hola.123"), "status": 1, "two_factor_enabled": False},
        {"username": "username4", "password": generate_password_hash("Hola.123"), "status": 1, "two_factor_enabled": False}
    ]
    for user in users:
        users_collection.update_one(
            {"username": user["username"]},
            {"$setOnInsert": user},
            upsert=True
        )

    tasks = [
        {
            "name": "name1",
            "description": "first task",
            "created_at": "2002-06-03",
            "dead_line": "2002-06-10",
            "status": "Completed",
            "is_alive": True,
            "created_by": "Bryan"
        },
        {
            "name": "name2",
            "description": "second task",
            "created_at": "2004-04-04",
            "dead_line": "2004-04-14",
            "status": "Paused",
            "is_alive": True,
            "created_by": "Sofia"
        }
    ]
    for task in tasks:
        tasks_collection.update_one(
            {"name": task["name"]},
            {"$setOnInsert": task},
            upsert=True
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
            return jsonify({'statusCode': 401, 'intData': {'message': 'Token inválido', 'data': None}}), 401
        return f(*args, **kwargs)
    return decorated

# Rutas
@app.route('/tasks', methods=['GET'])
@limiter.limit("30 per minute")
def get_tasks():
    tasks = list(tasks_collection.find())
    return jsonify({"statusCode": 200, "intData": {"message": "Tareas recuperadas con éxito", "data": [
        {"id": str(task["_id"]), **{k: v for k, v in task.items() if k != "_id"}}
        for task in tasks
    ]}})

@app.route('/id_tasks/<string:task_id>', methods=['GET'])
@limiter.limit("30 per minute")
@token_required
def id_task(task_id):
    try:
        task = tasks_collection.find_one({"_id": ObjectId(task_id)})
        if not task:
            return jsonify({"statusCode": 404, "intData": {"message": "Tarea no encontrada", "data": None}})
        task['id'] = str(task['_id'])
        del task['_id']
        return jsonify({"statusCode": 200, "intData": {"message": "Tarea recuperada con éxito", "data": task}})
    except ValueError:
        return jsonify({"statusCode": 400, "intData": {"message": "ID de tarea inválido", "data": None}})

@app.route('/Usertasks/<string:created_by>', methods=['GET'])
@limiter.limit("30 per minute")
@token_required
def get_task_created_by(created_by):
    tasks = list(tasks_collection.find({"created_by": created_by}))
    if not tasks:
        return jsonify({"statusCode": 404, "intData": {"message": "No se encontraron tareas para este usuario.", "data": []}})
    for task in tasks:
        task['id'] = str(task['_id'])
        del task['_id']
    return jsonify({"statusCode": 200, "intData": {"message": "Tareas recuperadas con éxito", "data": tasks}})

@app.route('/register_task', methods=['POST'])
@limiter.limit("30 per minute")
@token_required
def create_task():
    data = request.get_json()
    required_fields = ['name', 'description', 'created_at', 'dead_line', 'status', 'is_alive', 'created_by']
    if not all(field in data for field in required_fields):
        return jsonify({"statusCode": 400, "intData": {"message": "Todos los campos son requeridos", "data": None}})
    
    if data['status'] not in VALID_STATUSES:
        return jsonify({"statusCode": 400, "intData": {"message": f"El status debe ser uno de: {', '.join(VALID_STATUSES)}", "data": None}})
    
    if not validate_date(data['created_at']) or not validate_date(data['dead_line']):
        return jsonify({"statusCode": 400, "intData": {"message": "Formato de día inválido (YYYY-MM-DD)", "data": None}})
    
    if tasks_collection.find_one({"name": data["name"]}):
        return jsonify({"statusCode": 400, "intData": {"message": "El nombre de la tarea ya existe", "data": None}})
    
    result = tasks_collection.insert_one(data)
    data["id"] = str(result.inserted_id)
    if '_id' in data:
        del data['_id']
    return jsonify({"statusCode": 201, "intData": {"message": "Tarea creada exitosamente", "data": data}})

@app.route('/update_task/<string:task_id>', methods=['PUT'])
@limiter.limit("30 per minute")
@token_required
def edit_task(task_id):
    data = request.get_json()
    if '_id' in data:
        del data['_id']
    required_fields = ['name', 'description', 'created_at', 'dead_line', 'status', 'is_alive', 'created_by']
    if not all(field in data for field in required_fields):
        return jsonify({"statusCode": 400, "intData": {"message": "Todos los campos son requeridos", "data": None}})
    
    if data['status'] not in VALID_STATUSES:
        return jsonify({"statusCode": 400, "intData": {"message": f"El status debe ser uno de: {', '.join(VALID_STATUSES)}", "data": None}})
    
    if not validate_date(data['created_at']) or not validate_date(data['dead_line']):
        return jsonify({"statusCode": 400, "intData": {"message": "Formato de día inválido (YYYY-MM-DD)", "data": None}})
    
    try:
        obj_id = ObjectId(task_id)
        existing_task = tasks_collection.find_one({"name": data["name"], "_id": {"$ne": obj_id}})
        if existing_task:
            return jsonify({"statusCode": 400, "intData": {"message": "El nombre de la tarea ya existe", "data": None}})
        
        result = tasks_collection.update_one({"_id": obj_id}, {"$set": data})
        if result.matched_count == 0:
            return jsonify({"statusCode": 404, "intData": {"message": "Tarea no encontrada", "data": None}})
        return jsonify({"statusCode": 200, "intData": {"message": "Tarea editada exitosamente", "data": None}})
    except ValueError:
        return jsonify({"statusCode": 400, "intData": {"message": "ID de tarea inválido", "data": None}})

@app.route('/delete_task/<string:task_id>', methods=['DELETE'])
@limiter.limit("30 per minute")
@token_required
def delete_task(task_id):
    try:
        result = tasks_collection.delete_one({"_id": ObjectId(task_id)})
        if result.deleted_count == 0:
            return jsonify({"statusCode": 404, "intData": {"message": "Tarea no encontrada", "data": None}})
        return jsonify({"statusCode": 200, "intData": {"message": "Tarea eliminada exitosamente", "data": None}})
    except ValueError:
        return jsonify({"statusCode": 400, "intData": {"message": "ID de tarea inválido", "data": None}})

@app.route('/disable_task/<string:task_id>', methods=['PUT'])
@limiter.limit("30 per minute")
@token_required
def disable_task(task_id):
    try:
        result = tasks_collection.update_one({"_id": ObjectId(task_id)}, {"$set": {"is_alive": False}})
        if result.modified_count == 0:
            return jsonify({"statusCode": 404, "intData": {"message": "Tarea no encontrada para deshabilitar", "data": None}})
        return jsonify({"statusCode": 200, "intData": {"message": "Tarea deshabilitada exitosamente", "data": None}})
    except ValueError:
        return jsonify({"statusCode": 400, "intData": {"message": "ID de tarea inválido", "data": None}})

@app.route('/enable_task/<string:task_id>', methods=['PUT'])
@limiter.limit("30 per minute")
@token_required
def enable_task(task_id):
    try:
        result = tasks_collection.update_one({"_id": ObjectId(task_id)}, {"$set": {"is_alive": True}})
        if result.modified_count == 0:
            return jsonify({"statusCode": 404, "intData": {"message": "Tarea no encontrada para habilitar", "data": None}})
        return jsonify({"statusCode": 200, "intData": {"message": "Tarea habilitada exitosamente", "data": None}})
    except ValueError:
        return jsonify({"statusCode": 400, "intData": {"message": "ID de tarea inválido", "data": None}})

@app.route('/update_task_status/<string:task_id>', methods=['PUT'])
@limiter.limit("30 per minute")
@token_required
def update_task_status(task_id):
    data = request.get_json()
    if 'status' not in data:
        return jsonify({"statusCode": 400, "intData": {"message": "El campo status es obligatorio", "data": None}})
    status = data['status']
    if status not in VALID_STATUSES:
        return jsonify({"statusCode": 400, "intData": {"message": f"El status debe ser uno de: {', '.join(VALID_STATUSES)}", "data": None}})
    try:
        result = tasks_collection.update_one({"_id": ObjectId(task_id)}, {"$set": {"status": status}})
        if result.modified_count == 0:
            return jsonify({"statusCode": 404, "intData": {"message": "Tarea no encontrada para actualizar estado", "data": None}})
        return jsonify({"statusCode": 200, "intData": {"message": "Estado de la tarea actualizado exitosamente", "data": None}})
    except ValueError:
        return jsonify({"statusCode": 400, "intData": {"message": "ID de tarea inválido", "data": None}})

@app.route('/logs', methods=['GET'])
@limiter.limit("30 per minute")
@token_required
def get_logs():
    logs = list(task_logs_collection.find().sort("timestamp", -1))
    logs_list = [{"id": str(log["_id"]), **{k: v for k, v in log.items() if k != "_id"}} for log in logs]
    return jsonify({"statusCode": 200, "intData": {"message": "Logs recuperados con éxito", "data": logs_list}})

# Arranque de la app
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5003))
    app.run(host='0.0.0.0', port=port, debug=True)