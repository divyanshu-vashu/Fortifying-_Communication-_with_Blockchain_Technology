from flask import Flask, render_template, request, jsonify
import hashlib
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# AES encryption key and initialization vector
aes_key = os.urandom(32)  # AES-256 key
aes_iv = os.urandom(16)  # Initialization vector

# RSA key pair for digital signing
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

# Diffie-Hellman parameters
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
private_dh_key = parameters.generate_private_key()
public_dh_key = private_dh_key.public_key()

class Block:
    def __init__(self, data, previous_hash):
        self.timestamp = datetime.datetime.now()
        self.data = self.encrypt(data)
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
        self.signature = self.sign_block(self.hash)  # Digital signature for the block

    def encrypt(self, data):
        # AES encryption
        encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend()).encryptor()
        padded_data = data.ljust(32)  # Simple padding to 32 bytes for AES-256
        ciphertext = encryptor.update(padded_data.encode('utf-8')) + encryptor.finalize()
        return ciphertext.hex()  # Convert to hex for easy readability

    def calculate_hash(self):
        sha = hashlib.sha256()
        sha.update(
            str(self.timestamp).encode('utf-8') +
            str(self.data).encode('utf-8') +
            str(self.previous_hash).encode('utf-8')
        )
        return sha.hexdigest()

    def sign_block(self, hash_value):
        # Sign the block hash using RSA private key
        signature = private_key.sign(
            hash_value.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block("Genesis Block", "0")

    def add_block(self, data):
        previous_block = self.chain[-1]
        new_block = Block(data, previous_block.hash)
        self.chain.append(new_block)

    def is_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
            if not self.verify_signature(current_block.hash, current_block.signature):
                return False
        return True

    def decrypted_chain(self):
        decrypted_data = []
        for block in self.chain[1:]:  # Skip genesis block
            decrypted_data.append(self.decrypt(block.data))
        return decrypted_data

    def decrypt(self, encrypted_data):
        # AES decryption
        decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend()).decryptor()
        decrypted = decryptor.update(bytes.fromhex(encrypted_data)) + decryptor.finalize()
        return decrypted.decode('utf-8').strip()  # Strip padding

    def verify_signature(self, hash_value, signature):
        # Verify digital signature using RSA public key
        try:
            public_key.verify(
                bytes.fromhex(signature),
                hash_value.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# Initialize blockchain
blockchain = Blockchain()

# Initialize Flask app
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', blockchain=blockchain)

@app.route('/add_block', methods=['POST'])
def add_block():
    data = request.form['data']
    blockchain.add_block(data)
    return jsonify({
        "message": "Block added successfully!",
        "is_valid": blockchain.is_valid()
    })

@app.route('/get_chain')
def get_chain():
    chain_data = [{
        "timestamp": str(block.timestamp),
        "data": block.data,
        "previous_hash": block.previous_hash,
        "hash": block.hash,
        "signature": block.signature
    } for block in blockchain.chain]
    return jsonify(chain_data)

@app.route('/is_valid')
def is_valid():
    return jsonify({"is_valid": blockchain.is_valid()})

@app.route('/decrypted_chain')
def decrypted_chain():
    return jsonify(blockchain.decrypted_chain())

if __name__ == '__main__':
    app.run(debug=True)
