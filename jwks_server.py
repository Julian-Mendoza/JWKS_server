from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)

# Generate a RSA key pair for signing JWTs
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# JWKS with a unique key identifier (kid)
jwks = {
    'keys': [
        {
            'kid': 'mykid',
            'kty': 'RSA',
            'alg': 'RS256',
            'use': 'sig',
            'n': public_key.public_numbers().n,
            'e': public_key.public_numbers().e,
        }
    ]
}

# Token expiration time
token_expiry_time = timedelta(minutes=30)

@app.route('/jwks', methods=['GET'])
def get_jwks():
    return jsonify(jwks)

@app.route('/auth', methods=['POST'])
def authenticate():
    # Get the JWT from the request
    token = request.json.get('token')

    try:
        # Verify the JWT with our public key
        decoded_token = jwt.decode(token, public_pem, algorithms=['RS256'])

        # Check if the token has expired
        if datetime.utcfromtimestamp(decoded_token['exp']) < datetime.utcnow():
            return jsonify({'message': 'Token has expired'}), 401

        return jsonify({'message': 'Authentication successful'})
    except jwt.ExpiredSignatureError:
        # Token has expired
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.DecodeError:
        # Token is invalid
        return jsonify({'message': 'Invalid token'}), 401

@app.route('/issue_jwt', methods=['GET'])
def issue_jwt():
    # Create a JWT with an expired key if the query parameter 'expired' is set to 'true'
    expired = request.args.get('expired')
    if expired == 'true':
        expiry_time = datetime.utcnow() - token_expiry_time
    else:
        expiry_time = datetime.utcnow() + token_expiry_time

    token = jwt.encode({
        'exp': expiry_time,
        'sub': 'user123'
    }, private_pem, algorithm='RS256')

    return jsonify({'token': token})

if __name__ == '__main__':
    app.run(debug=True)
