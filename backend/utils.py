import hashlib
import json


def hash_block(block):
    """
    Generate a SHA-256 hash of a block.
    Args:
        block (dict): The block to hash.
    Returns:
        str: The hash of the block.
    """
    if not isinstance(block, dict):
        raise ValueError("Invalid block format. Expected a dictionary.")

    try:
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    except Exception as e:
        raise ValueError(f"Error hashing block: {e}")


def calculate_proof_hash(previous_proof, proof):
    """
    Calculate the hash for a given proof and previous proof.
    Args:
        previous_proof (int): The proof of the previous block.
        proof (int): The current proof.
    Returns:
        str: The hash of the proof.
    """
    return hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()


def is_proof_valid(previous_proof, proof, difficulty=4):
    """
    Validate the proof of work by checking the hash.
    Args:
        previous_proof (int): The proof of the previous block.
        proof (int): The current proof to validate.
        difficulty (int): The number of leading zeros required in the hash.
    Returns:
        bool: True if the proof is valid, False otherwise.
    """
    hash_operation = calculate_proof_hash(previous_proof, proof)
    return hash_operation[:difficulty] == "0" * difficulty


def is_chain_valid(chain, difficulty=4):
    """
    Validate the blockchain.
    Args:
        chain (list): The blockchain to validate.
        difficulty (int): The number of leading zeros required for proof validation.
    Returns:
        bool: True if the blockchain is valid, False otherwise.
    """
    for i in range(1, len(chain)):
        current_block = chain[i]
        previous_block = chain[i - 1]

        # Check if the previous hash matches
        if current_block['previous_hash'] != hash_block(previous_block):
            print(f"Invalid previous hash at block {i}.")
            return False

        # Check if the proof of work is valid
        if not is_proof_valid(previous_block['proof'], current_block['proof'], difficulty):
            print(f"Invalid proof of work at block {i}.")
            return False

    return True


def save_to_file(data, filename):
    """
    Save data to a file in JSON format.
    Args:
        data: The data to save.
        filename (str): The file path to save data to.
    """
    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        raise IOError(f"Failed to save data to {filename}: {e}")


def load_from_file(filename):
    """
    Load data from a JSON file.
    Args:
        filename (str): The file path to load data from.
    Returns:
        dict or list: The loaded data, or an empty list if the file doesn't exist or is invalid.
    """
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
            if not isinstance(data, (list, dict)):
                raise ValueError("Invalid data format in file.")
            return data
    except FileNotFoundError:
        return []
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Error loading JSON from {filename}: {e}")
        return []
