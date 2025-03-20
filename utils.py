import hashlib
import logging
import os
from datetime import datetime
def setup_logger(name, log_file, level=logging.INFO):
    """Sets up a logger that writes to both a file and the console"""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger
def calculate_file_hash(file_path):
    """Calculates the SHA-256 hash of a file for integrity verification"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
def get_file_size(file_path):
    """Returns the size of a file in bytes"""
    return os.path.getsize(file_path)
def handle_duplicate_filename(directory, filename):
    """
    Handles duplicate filenames by adding version numbers (e.g., file_v2.txt)
    Returns the new filename and whether it was a duplicate
    """
    base_name, extension = os.path.splitext(filename)
    counter = 1
    new_filename = filename
    while os.path.exists(os.path.join(directory, new_filename)):
        counter += 1
        new_filename = f"{base_name}_v{counter}{extension}"
    return new_filename, counter > 1
def create_timestamp():
    """Creates a human-readable timestamp for logging purposes"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def chunk_file(file_path, chunk_size=8192):
    """Reads a file in chunks to efficiently handle large files"""
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk 