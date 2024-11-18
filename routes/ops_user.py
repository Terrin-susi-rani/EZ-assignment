from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
import os
from config import Config

ops_user = Blueprint('ops_user', __name__)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@ops_user.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(Config.UPLOAD_FOLDER, filename))
        return jsonify({"message": "File uploaded successfully"}), 200
    return jsonify({"error": "Invalid file type"}), 400
