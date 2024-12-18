from flask import Flask, render_template, request, jsonify
import hashlib
import datetime

# Blockchain classes
class Block:
    def __init__(self, data, previous_hash):
        self.timestamp = datetime.datetime.now()
        self.data = self.encrypt(data)
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def encrypt(self, data):
        encrypted_data = "".join(chr(ord(char) + 4) for char in data)  # Shift each character by 4
        return encrypted_data

    def calculate_hash(self):
        sha = hashlib.sha256()
        sha.update(
            str(self.timestamp).encode('utf-8') +
            str(self.data).encode('utf-8') +
            str(self.previous_hash).encode('utf-8')
        )
        return sha.hexdigest()

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
        return True

    def decrypted_chain(self):
        decrypted_data = []
        for i in range(1, len(self.chain)):  # Skip the genesis block
            encrypted_data = self.chain[i].data
            decrypted_data.append("".join(chr(ord(char) - 4) for char in encrypted_data))
        return decrypted_data

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
    return jsonify({"message": "Block added successfully!", "is_valid": blockchain.is_valid()})

@app.route('/get_chain')
def get_chain():
    chain_data = [{
        "timestamp": str(block.timestamp),
        "data": block.data,
        "previous_hash": block.previous_hash,
        "hash": block.hash
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
