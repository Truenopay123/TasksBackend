from flask import Flask, jsonify, request
import jwt
from flask_cors import CORS  # type: ignore
import datetime
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp  # type: ignore
import qrcode  # type: ignore
from io import BytesIO
import base64
from flask_limiter import Limiter  # type: ignore
from flask_limiter.util import get_remote_address  # type: ignore
from pymongo import MongoClient  # type: ignore
import os  # Agregado para variables de entorno

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get('SECRET_KEY', 'QHZ/5n4Y+AugECPP12uVY/9mWZ14nqEfdiBB8Jo6//g')
client = MongoClient(os.environ.get('MONGO_URI', 'mongodb+srv://2023171002:1234@cluster0.rquhrnu.mongodb.net/auth_db?retryWrites=true&w=majority&appName=Cluster0'))
db = client['auth_db']
users_collection = db['users']

limiter = Limiter(
    get_remote_address,
    default_limits=["100 per minute"]
)

def init_db():
    users = [
        {"username": "user1", "password": generate_password_hash("pass1"), "two_factor_secret": None, "two_factor_enabled": False},
        {"username": "user2", "password": generate_password_hash("pass2"), "two_factor_secret": None, "two_factor_enabled": False}
    ]
    for user in users:
        if not users_collection.find_one({"username": user["username"]}):
            users_collection.insert_one(user)

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
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    return jsonify({"statusCode": 200, "intData": {"message": "Login exitoso", "token": token}})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)