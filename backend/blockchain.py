import os
from utils import hash_block, is_proof_valid, is_chain_valid, save_to_file, load_from_file
import datetime
import logging

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BLOCKCHAIN_FILE = os.path.join(BASE_DIR, 'blockchain.json')

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class Blockchain:
    def __init__(self):
        """Initialize the blockchain or load it from file."""
        self.chain = load_from_file(BLOCKCHAIN_FILE) or []
        self.pending_transactions = []
        
        if not self.chain:
            logging.info("No existing blockchain found. Creating Genesis Block.")
            self.create_genesis_block()
        else:
            try:
                self.validate_chain_on_load()
                logging.info("Blockchain successfully loaded and validated.")
            except ValueError as e:
                logging.error(f"Blockchain validation failed on load: {e}")
                raise

    def create_genesis_block(self):
        """Create the Genesis Block."""
        self.create_block(proof=1, previous_hash='0')

    def is_genesis_block_valid(self):
        """Validate the genesis block."""
        if len(self.chain) == 0:
            return False
        genesis_block = self.chain[0]
        return genesis_block['previous_hash'] == '0' and genesis_block['proof'] == 1

    def create_block(self, proof, previous_hash):
        """Create a new block and add it to the blockchain."""
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.pending_transactions
        }
        self.pending_transactions = []  # Clear pending transactions after block is created
        self.chain.append(block)

        try:
            save_to_file(self.chain, BLOCKCHAIN_FILE)
            logging.info(f"Block {block['index']} created and saved successfully.")
        except Exception as e:
            logging.error(f"Error saving blockchain to file: {e}")

        return block

    def get_last_block(self):
        """Return the last block in the blockchain."""
        return self.chain[-1]

    def add_transaction(self, sender, receiver, amount):
        """Add a new transaction to the list of pending transactions."""
        if not sender or not receiver or amount <= 0:
            logging.error("Invalid transaction. Sender, receiver, and amount must be valid.")
            return None
        
        transaction = {
            'sender': sender,
            'receiver': receiver,
            'amount': amount,
            'timestamp': str(datetime.datetime.now())
        }
        self.pending_transactions.append(transaction)
        logging.info(f"Transaction added: {transaction}")
        return self.get_last_block()['index'] + 1

    def proof_of_work(self, previous_proof, difficulty=4):
        """Proof of Work algorithm with adjustable difficulty."""
        new_proof = 1
        while not is_proof_valid(previous_proof, new_proof, difficulty):
            new_proof += 1
        logging.info(f"Proof of Work found: {new_proof} for difficulty: {difficulty}")
        return new_proof

    def is_chain_valid(self):
        """Check if the blockchain is valid."""
        valid = is_chain_valid(self.chain)
        if not valid:
            logging.error("Blockchain validation failed.")
        return valid

    def get_blockchain(self):
        """Return the entire blockchain."""
        return self.chain

    def get_user_transactions(self, username, filter_type='all'):
        """Retrieve transactions involving a specific user with optional filtering."""
        transactions = [
            transaction for block in self.chain for transaction in block['transactions']
            if (filter_type == 'all' and (transaction['sender'] == username or transaction['receiver'] == username)) or
               (filter_type == 'sent' and transaction['sender'] == username) or
               (filter_type == 'received' and transaction['receiver'] == username)
        ]
        logging.info(f"Transactions for {username} (Filter: {filter_type}): {transactions}")
        return transactions

    def validate_chain_on_load(self):
        """Validate the blockchain when loading."""
        if not self.is_chain_valid():
            raise ValueError("Loaded blockchain is invalid.")

    def get_blockchain_summary(self):
        """Get a summary of the blockchain."""
        summary = {
            'total_blocks': len(self.chain),
            'total_transactions': sum(len(block['transactions']) for block in self.chain),
            'pending_transactions': len(self.pending_transactions)
        }
        logging.info(f"Blockchain Summary: {summary}")
        return summary
