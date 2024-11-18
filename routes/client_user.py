from flask import Blueprint, request, jsonify
from utils.encryption import encrypt_url, decrypt_url
from utils.auth import authenticate_user
from utils.email import send_verification_email

client_user = Blueprint('client_user', __name__)

@client_user.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    # Save user to the database and generate verification URL
    encrypted_url = encrypt_url(data['email'])
    send_verification_email(data['email'], encrypted_url)
    return jsonify({"message": "Verification email sent"}), 201

@client_user.route('/verify-email/<encrypted_url>', methods=['GET'])
def verify_email(encrypted_url):
    email = decrypt_url(encrypted_url)
    # Update the user in the database to mark email as verified
    return jsonify({"message": "Email verified successfully"}), 200

@client_user.route('/files', methods=['GET'])
@authenticate_user
def list_files():
    # Query and return list of uploaded files from the database
    return jsonify({"files": []}), 200
