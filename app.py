from flask import Flask, request, jsonify, send_from_directory
from flask_bcrypt import Bcrypt
from flask_jwt_extended import jwt_required, create_access_token
from werkzeug.utils import secure_filename
from config import Config
from utils import allowed_file, init_jwt
import os

app = Flask(__name__)
app.config.from_object(Config)
bcrypt = Bcrypt(app)
jwt = init_jwt(app)

# Dummy in-memory database
users = []  # To store user credentials
files = []  # To store uploaded file metadata

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


### Routes

# 1. Ops User Login
@app.route('/ops/login', methods=['POST'])
def ops_login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Hardcoded Ops User (you can later connect to a real DB)
    if username == "ops_user" and password == "securepassword":
        token = create_access_token(identity={"username": username, "role": "ops"})
        return jsonify({"message": "Login successful", "token": token}), 200
    return jsonify({"error": "Invalid credentials"}), 401


# 2. Upload File (Ops User Only)
@app.route('/ops/upload', methods=['POST'])
@jwt_required()
def upload_file():
    current_user = get_jwt_identity()
    if current_user.get("role") != "ops":
        return jsonify({"error": "Unauthorized"}), 403

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file and allowed_file(file.filename, app.config['ALLOWED_EXTENSIONS']):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Store file metadata
        files.append({"filename": filename, "uploaded_by": current_user["username"]})
        return jsonify({"message": "File uploaded successfully"}), 200

    return jsonify({"error": "Invalid file type"}), 400


# 3. Client User Signup
@app.route('/client/signup', methods=['POST'])
def client_signup():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Add user to in-memory DB
    users.append({"email": email, "password": hashed_password, "role": "client"})
    return jsonify({"message": "Signup successful"}), 201


# 4. Client User Login
@app.route('/client/login', methods=['POST'])
def client_login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = next((u for u in users if u["email"] == email), None)
    if user and bcrypt.check_password_hash(user["password"], password):
        token = create_access_token(identity={"email": email, "role": "client"})
        return jsonify({"message": "Login successful", "token": token}), 200

    return jsonify({"error": "Invalid credentials"}), 401


# 5. List Uploaded Files (Client User Only)
@app.route('/client/files', methods=['GET'])
@jwt_required()
def list_files():
    current_user = get_jwt_identity()
    if current_user.get("role") != "client":
        return jsonify({"error": "Unauthorized"}), 403

    return jsonify({"files": files}), 200


# 6. Download File (Client User Only)
@app.route('/client/files/download/<filename>', methods=['GET'])
@jwt_required()
def download_file(filename):
    current_user = get_jwt_identity()
    if current_user.get("role") != "client":
        return jsonify({"error": "Unauthorized"}), 403

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename), 200

    return jsonify({"error": "File not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)
