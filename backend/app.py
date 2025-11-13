from utils import hash_block, is_proof_valid, is_chain_valid, save_to_file, load_from_file
from blockchain import Blockchain, BLOCKCHAIN_FILE
from flask import Flask, jsonify, request, send_from_directory, render_template, redirect, url_for
import bcrypt
import json
import os
import requests
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# Global list to store peer URLs
peers = []

# Initialize Flask app with correct template folder (templates folder is one level up from backend)
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'templates'))
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True  # Pretty JSON formatting

# JWT Config
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
jwt = JWTManager(app)

# Initialize Blockchain instance
blockchain = Blockchain()

# File paths
USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'users.json')
FRONTEND_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'frontend')
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PEERS_FILE = os.path.join(BASE_DIR, 'peers.json')

# Utility Functions
def load_peers():
    try:
        with open(PEERS_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []  # No peers registered yet
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Error loading peers: {e}")
        return []

def save_peers(peers):
    try:
        with open(PEERS_FILE, 'w') as file:
            json.dump(peers, file, indent=4)
    except Exception as e:
        print(f"Error saving peers: {e}")

def load_users():
    try:
        with open(USERS_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open(USERS_FILE, 'w') as file:
        json.dump(users, file, indent=4)

def broadcast_block(new_block):
    peers = load_peers()  # Load the persisted peers
    for peer in peers:
        try:
            url = f"{peer}/receive_block"
            response = requests.post(url, json={"block": new_block})
            print(f"Broadcast to {peer}: {response.json()}")
        except Exception as e:
            print(f"Could not broadcast to {peer}: {e}")

# Routes for serving static frontend pages (no dynamic data)
@app.route("/")
def home():
    return send_from_directory(FRONTEND_FOLDER, "index.html")

@app.route("/login_page")
def login_page():
    return send_from_directory(FRONTEND_FOLDER, "login.html")

@app.route("/signup_page")
def signup_page():
    return send_from_directory(FRONTEND_FOLDER, "signup.html")

@app.route('/mine_block')
def mine_block_page():
    return render_template('mining_result.html')

# Dynamic Pages: Render templates (no JWT protection here; we use cookie for user info)
@app.route("/dashboard")
def dashboard():
    current_user = request.cookies.get("username")
    users = load_users()
    if not current_user or current_user not in users:
        return redirect(url_for("login_page"))
    
    user_data = {
        'username': current_user,
        'balance': users[current_user]['balance'],
        'transactions': blockchain.get_user_transactions(current_user)
    }
    return render_template("dashboard.html", user=user_data)

@app.route("/deposit", methods=["GET", "POST"])
def deposit():
    current_user = request.cookies.get("username")
    users = load_users()
    if not current_user or current_user not in users:
        return redirect(url_for("login_page"))

    if request.method == "POST":
        # Check if the request data is JSON or form data:
        if request.is_json:
            data = request.get_json()
            amount = float(data.get("amount", 0))
        else:
            amount = float(request.form.get("amount", 0))
        
        if amount <= 0:
            # Return JSON error response for AJAX requests
            if request.is_json:
                return jsonify({'status': 'error', 'message': 'Deposit amount must be greater than zero.'}), 400
            else:
                return redirect(url_for("dashboard"))
        
        users[current_user]['balance'] += amount
        blockchain.add_transaction(sender="SYSTEM", receiver=current_user, amount=amount)
        save_users(users)
        
        # Return a JSON response if the request is JSON,
        # otherwise perform a redirect.
        if request.is_json:
            return jsonify({'status': 'success', 'message': f'₹{amount} deposited successfully!'}), 200
        else:
            return redirect(url_for("dashboard"))
    
    user_data = {
        'username': current_user,
        'balance': users[current_user]['balance']
    }
    return render_template("deposit.html", user=user_data)

@app.route("/send_amount", methods=["GET", "POST"])
def send_amount():
    current_user = request.cookies.get("username")
    users = load_users()
    if not current_user or current_user not in users:
        return redirect(url_for("login_page"))

    if request.method == "POST":
        # Handle both JSON and form submissions
        if request.is_json:
            data = request.get_json()
            receiver = data.get("receiver")
            amount = float(data.get("amount", 0))
        else:
            receiver = request.form.get("receiver")
            amount = float(request.form.get("amount", 0))

        # Validate required fields
        if not receiver:
            return jsonify({'status': 'error', 'message': 'Receiver is missing.'}), 400

        if receiver not in users:
            return jsonify({'status': 'error', 'message': 'Receiver not found.'}), 404

        if users[current_user]['balance'] < amount:
            return jsonify({'status': 'error', 'message': 'Insufficient balance.'}), 400

        # Process the transaction
        users[current_user]['balance'] -= amount
        users[receiver]['balance'] += amount
        blockchain.add_transaction(sender=current_user, receiver=receiver, amount=amount)
        save_users(users)

        # If request is JSON (AJAX), return a JSON response; else, redirect
        if request.is_json:
            return jsonify({'status': 'success', 'message': f'₹{amount} sent to {receiver}.'}), 200
        else:
            return redirect(url_for("transactions"))

    # GET method: Render the send-amount page
    user_data = {
        'username': current_user,
        'balance': users[current_user]['balance']
    }
    return render_template("send-amount.html", user=user_data)

@app.route("/transactions")
def transactions():
    current_user = request.cookies.get("username")
    if not current_user:
        return redirect(url_for("login_page"))
    
    # Load user data
    users = load_users()
    if current_user not in users:
        return redirect(url_for("login_page"))
    
    # Confirmed transactions from the blockchain (mined blocks)
    confirmed_transactions = blockchain.get_user_transactions(current_user)
    
    # Pending transactions (not yet mined into a block)
    pending_transactions = [
        {**tx, "pending": True} for tx in blockchain.pending_transactions 
        if tx.get("sender") == current_user or tx.get("receiver") == current_user
    ]
    
    # Combine both lists (order can be adjusted as needed)
    all_transactions = confirmed_transactions + pending_transactions
    
    user_data = {
        'balance': users[current_user]['balance']
    }
    
    return render_template("transactions.html", transactions=all_transactions, user=user_data)

# API Routes (Protected by JWT where appropriate)
@app.route('/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    required_fields = ['username', 'password', 'email', 'address', 'gender']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'status': 'error', 'message': 'Missing required fields.'}), 400
    users = load_users()
    username = data['username']
    if username in users:
        return jsonify({'status': 'error', 'message': 'Username already exists.'}), 400
    hashed_password = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
    users[username] = {
        'password': hashed_password,
        'email': data['email'],
        'address': data['address'],
        'gender': data['gender'],
        'balance': 0
    }
    save_users(users)
    return jsonify({'status': 'success', 'message': 'User registered successfully!'}), 201

@app.route('/login', methods=['POST'])
def api_login():
    data = request.get_json()
    required_fields = ['username', 'password']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'status': 'error', 'message': 'Missing required fields.'}), 400
    users = load_users()
    username = data['username']
    if username not in users or not bcrypt.checkpw(data['password'].encode(), users[username]['password'].encode()):
        return jsonify({'status': 'error', 'message': 'Invalid credentials.'}), 401
    token = create_access_token(identity=username)
    response = jsonify({
        'status': 'success',
        'message': 'Login successful!',
        'token': token,
        'user_details': {
            'username': username,
            'email': users[username]['email'],
            'balance': users[username]['balance'],
            'transactions': blockchain.get_user_transactions(username)
        }
    })
    # Set a cookie with the username for dynamic pages
    response.set_cookie("username", username, domain=request.host.split(":")[0], httponly=True)
    return response, 200

@app.route('/deposit', methods=['POST'])
def api_deposit():
    data = request.get_json()
    required_fields = ['username', 'amount']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'status': 'error', 'message': 'Missing required fields.'}), 400
    users = load_users()
    username = data['username']
    amount = data['amount']
    if username not in users:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404
    users[username]['balance'] += amount
    blockchain.add_transaction(sender="SYSTEM", receiver=username, amount=amount)
    save_users(users)
    return jsonify({'status': 'success', 'message': f'₹{amount} deposited successfully!'}), 200

@app.route('/send_amount', methods=['POST'])
@jwt_required()
def api_send_amount():
    current_user = get_jwt_identity()
    data = request.get_json()
    required_fields = ['receiver', 'amount']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'status': 'error', 'message': 'Missing required fields.'}), 400
    users = load_users()
    receiver = data['receiver']
    amount = data['amount']
    if current_user not in users or receiver not in users:
        return jsonify({'status': 'error', 'message': 'Invalid sender or receiver.'}), 404
    if users[current_user]['balance'] < amount:
        return jsonify({'status': 'error', 'message': 'Insufficient balance.'}), 400
    users[current_user]['balance'] -= amount
    users[receiver]['balance'] += amount
    blockchain.add_transaction(sender=current_user, receiver=receiver, amount=amount)
    save_users(users)
    return jsonify({'status': 'success', 'message': f'₹{amount} sent to {receiver}.'}), 200

@app.route('/mine_block_api')
def mine_block_api():
    try:
        last_block = blockchain.get_last_block()
        proof = blockchain.proof_of_work(last_block['proof'])
        previous_hash = hash_block(last_block)
        new_block = blockchain.create_block(proof, previous_hash)

        broadcast_block(new_block)

        response = {
            'status': 'success',
            'message': 'A new block has been mined and broadcasted.',
            'block_details': new_block,
            'chain_length': len(blockchain.chain)
        }
        return jsonify(response), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get_chain', methods=['GET'])
def get_chain():
    try:
        chain = blockchain.chain
        return render_template('blockchain.html', chain=chain, length=len(chain))
    except Exception as e:
        return render_template('error.html', message=str(e)), 500

@app.route('/validate_chain', methods=['GET'])
def validate_chain():
    try:
        is_valid = blockchain.is_chain_valid()
        message = '✅ The blockchain is valid.' if is_valid else '❌ The blockchain is invalid.'
        return render_template('validate_chain.html', is_valid=is_valid, message=message)
    except Exception as e:
        return render_template('validate_chain.html', is_valid=False, message=f"Error: {str(e)}")

@app.route('/pending_transactions', methods=['GET'])
def pending_transactions():
    try:
        return render_template('pending_transactions.html', transactions=blockchain.pending_transactions)
    except Exception as e:
        return f"<h3>Error loading transactions: {str(e)}</h3>", 500

@app.route('/network_info', methods=['GET'])
def network_info():
    try:
        network_data = {
            'total_blocks': len(blockchain.chain),
            'pending_transactions': len(blockchain.pending_transactions)
        }
        return render_template('network_info.html', network=network_data)
    except Exception as e:
        return render_template('error.html', message=str(e))

@app.route('/user_transactions/<username>', methods=['GET'])
def user_transactions(username):
    try:
        transactions = blockchain.get_user_transactions(username)
        return jsonify({'status': 'success', 'transactions': transactions}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/register_peer', methods=['POST'])
def register_peer():
    data = request.get_json()
    peer = data.get("peer")
    if not peer:
        return jsonify({'status': 'error', 'message': 'Peer URL is missing.'}), 400
    
    # Load existing peers from file
    peers = load_peers()
    if peer not in peers:
        peers.append(peer)
        save_peers(peers)
        return jsonify({'status': 'success', 'message': f'Peer {peer} registered successfully!', 'peers': peers}), 201
    else:
        return jsonify({'status': 'error', 'message': 'Peer already registered.'}), 400

@app.route('/get_peers', methods=['GET'])
def get_peers():
    peers = load_peers()
    return jsonify({'status': 'success', 'peers': peers}), 200

@app.route('/receive_block', methods=['POST'])
def receive_block():
    data = request.get_json()
    new_block = data.get("block")
    if not new_block:
        return jsonify({'status': 'error', 'message': 'No block data provided.'}), 400

    # Validate the new block before adding (you need to implement your own validation logic)
    # For example, check if the new block's previous_hash matches your last block's hash.
    last_block = blockchain.get_last_block()
    if new_block['previous_hash'] != hash_block(last_block):
        return jsonify({'status': 'error', 'message': 'Invalid block: Previous hash does not match.'}), 400

    # Add the new block to the chain and clear pending transactions
    blockchain.chain.append(new_block)
    blockchain.pending_transactions = []  # Optionally clear pending transactions if they are included
    try:
        save_to_file(blockchain.chain, BLOCKCHAIN_FILE)
        return jsonify({'status': 'success', 'message': 'Block received and added to chain.'}), 201
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/sync_chain', methods=['GET'])
def sync_chain():
    global blockchain
    longest_chain = blockchain.chain
    for peer in peers:
        try:
            response = requests.get(f"{peer}/get_chain")
            if response.status_code == 200:
                peer_chain = response.json().get("chain")
                if peer_chain and len(peer_chain) > len(longest_chain) and is_chain_valid(peer_chain):
                    longest_chain = peer_chain
        except Exception as e:
            print(f"Error syncing with peer {peer}: {e}")

    if longest_chain != blockchain.chain:
        blockchain.chain = longest_chain
        save_to_file(blockchain.chain, BLOCKCHAIN_FILE)
        return jsonify({'status': 'success', 'message': 'Chain updated from peer.'}), 200
    else:
        return jsonify({'status': 'success', 'message': 'Local chain is the longest.'}), 200

@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('FLASK_RUN_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)



"""
TO regester peers:

curl -X POST http://node1.localhost:5000/register_peer -H "Content-Type: application/json" -d "{\"peer\": \"http://node1.localhost:5001\"}"
"""
