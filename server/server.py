import os
import socket
import threading
import json
import time
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import setup_logger, calculate_file_hash, handle_duplicate_filename, get_file_size
from protocol import (
    receive_message, send_message, create_response,
    CMD_UPLOAD, CMD_DOWNLOAD, CMD_LIST, CMD_AUTH, CMD_RESUME,
    STATUS_OK, STATUS_ERROR, STATUS_AUTH_REQUIRED, STATUS_AUTH_SUCCESS, 
    STATUS_AUTH_FAILED, STATUS_FILE_NOT_FOUND, STATUS_CHECKSUM_FAILED,
    CHUNK_SIZE
)
from database import Database, ROLE_ADMIN, ROLE_USER
HOST = '0.0.0.0'  
PORT = 9000
SHARED_FILES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'shared_files')
DOWNLOAD_TEMP_DIR = os.path.join(SHARED_FILES_DIR, 'temp')
REQUIRE_AUTH = True  
os.makedirs(SHARED_FILES_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_TEMP_DIR, exist_ok=True)
logger = setup_logger('server', 'logs/server.log')
db = Database()
active_clients = {}
active_clients_lock = threading.Lock()
incomplete_uploads = {}
incomplete_uploads_lock = threading.Lock()
class ClientHandler(threading.Thread):
    def __init__(self, client_socket, client_address):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.client_address = client_address
        self.authenticated = not REQUIRE_AUTH
        self.username = None
        self.role = None
        self.running = True
        with active_clients_lock:
            active_clients[client_address] = self
    def run(self):
        """Handles all communication with a connected client"""
        logger.info(f"New connection from {self.client_address}")
        try:
            while self.running:
                message = receive_message(self.client_socket)
                if not message:
                    logger.info(f"Client {self.client_address} disconnected")
                    break
                command = message.get('command')
                data = message.get('data', {})
                if REQUIRE_AUTH and not self.authenticated and command != CMD_AUTH:
                    response = create_response(STATUS_AUTH_REQUIRED)
                    send_message(self.client_socket, 'RESPONSE', response)
                    continue
                if command == CMD_AUTH:
                    self.handle_auth(data)
                elif command == CMD_UPLOAD:
                    self.handle_upload(data)
                elif command == CMD_DOWNLOAD:
                    self.handle_download(data)
                elif command == CMD_LIST:
                    self.handle_list()
                elif command == CMD_RESUME:
                    self.handle_resume_upload(data)
                else:
                    logger.warning(f"Unknown command from {self.client_address}: {command}")
                    response = create_response(STATUS_ERROR, {'message': 'Unknown command'})
                    send_message(self.client_socket, 'RESPONSE', response)
        except Exception as e:
            logger.error(f"Error handling client {self.client_address}: {str(e)}")
        finally:
            self.client_socket.close()
            with active_clients_lock:
                if self.client_address in active_clients:
                    del active_clients[self.client_address]
            logger.info(f"Connection closed with {self.client_address}")
    def handle_auth(self, data):
        """Verifies client credentials and establishes authenticated session"""
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            response = create_response(STATUS_ERROR, {'message': 'Missing username or password'})
            send_message(self.client_socket, 'RESPONSE', response)
            return
        success, role = db.authenticate_user(username, password)
        if success:
            self.authenticated = True
            self.username = username
            self.role = role
            response = create_response(STATUS_AUTH_SUCCESS, {'role': role})
            logger.info(f"Client {self.client_address} authenticated as {username} with role {role}")
        else:
            response = create_response(STATUS_AUTH_FAILED)
            logger.warning(f"Failed authentication attempt from {self.client_address}")
        send_message(self.client_socket, 'RESPONSE', response)
    def handle_upload(self, data):
        """Processes incoming file uploads from clients"""
        filename = data.get('filename')
        file_size = data.get('file_size')
        file_hash = data.get('file_hash')
        overwrite = data.get('overwrite', False)
        if not filename or file_size is None:
            response = create_response(STATUS_ERROR, {'message': 'Missing filename or file size'})
            send_message(self.client_socket, 'RESPONSE', response)
            return
        target_path = os.path.join(SHARED_FILES_DIR, filename)
        if os.path.exists(target_path) and not overwrite:
            new_filename, is_duplicate = handle_duplicate_filename(SHARED_FILES_DIR, filename)
            target_path = os.path.join(SHARED_FILES_DIR, new_filename)
            logger.info(f"File {filename} already exists, renamed to {new_filename}")
        temp_path = os.path.join(DOWNLOAD_TEMP_DIR, f"{filename}.part")
        response = create_response(STATUS_OK, {
            'ready': True,
            'temp_id': filename  
        })
        send_message(self.client_socket, 'RESPONSE', response)
        try:
            with open(temp_path, 'wb') as f:
                bytes_received = 0
                start_time = time.time()
                while bytes_received < file_size:
                    chunk = self.client_socket.recv(min(CHUNK_SIZE, file_size - bytes_received))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
                    with incomplete_uploads_lock:
                        incomplete_uploads[filename] = {
                            'path': temp_path,
                            'target_path': target_path,
                            'bytes_received': bytes_received,
                            'file_size': file_size,
                            'file_hash': file_hash
                        }
                if bytes_received < file_size:
                    logger.warning(f"Incomplete upload from {self.client_address}: {filename} ({bytes_received}/{file_size} bytes)")
                    response = create_response(STATUS_ERROR, {
                        'message': 'Incomplete upload',
                        'bytes_received': bytes_received,
                        'resumable': True
                    })
                    send_message(self.client_socket, 'RESPONSE', response)
                    return
                calculated_hash = calculate_file_hash(temp_path)
                if file_hash and calculated_hash != file_hash:
                    logger.warning(f"Checksum failed for upload from {self.client_address}: {filename}")
                    response = create_response(STATUS_CHECKSUM_FAILED)
                    send_message(self.client_socket, 'RESPONSE', response)
                    return
                os.rename(temp_path, target_path)
                with incomplete_uploads_lock:
                    if filename in incomplete_uploads:
                        del incomplete_uploads[filename]
                elapsed_time = time.time() - start_time
                transfer_rate = file_size / (1024 * 1024 * elapsed_time) if elapsed_time > 0 else 0
                logger.info(f"Upload complete from {self.client_address}: {filename} ({file_size} bytes, {transfer_rate:.2f} MB/s)")
                response = create_response(STATUS_OK, {
                    'message': 'Upload successful',
                    'filename': os.path.basename(target_path),
                    'size': file_size,
                    'hash': calculated_hash
                })
                send_message(self.client_socket, 'RESPONSE', response)
        except Exception as e:
            logger.error(f"Error during upload from {self.client_address}: {str(e)}")
            response = create_response(STATUS_ERROR, {'message': str(e)})
            send_message(self.client_socket, 'RESPONSE', response)
    def handle_resume_upload(self, data):
        """Continues a previously interrupted file upload"""
        filename = data.get('filename')
        file_hash = data.get('file_hash')
        if not filename:
            response = create_response(STATUS_ERROR, {'message': 'Missing filename'})
            send_message(self.client_socket, 'RESPONSE', response)
            return
        with incomplete_uploads_lock:
            if filename not in incomplete_uploads:
                response = create_response(STATUS_ERROR, {'message': 'No incomplete upload found'})
                send_message(self.client_socket, 'RESPONSE', response)
                return
            upload_info = incomplete_uploads[filename]
        response = create_response(STATUS_OK, {
            'bytes_received': upload_info['bytes_received'],
            'file_size': upload_info['file_size']
        })
        send_message(self.client_socket, 'RESPONSE', response)
        try:
            with open(upload_info['path'], 'ab') as f:
                bytes_received = upload_info['bytes_received']
                file_size = upload_info['file_size']
                start_time = time.time()
                while bytes_received < file_size:
                    chunk = self.client_socket.recv(min(CHUNK_SIZE, file_size - bytes_received))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
                    with incomplete_uploads_lock:
                        incomplete_uploads[filename]['bytes_received'] = bytes_received
                if bytes_received < file_size:
                    logger.warning(f"Incomplete resumed upload from {self.client_address}: {filename} ({bytes_received}/{file_size} bytes)")
                    response = create_response(STATUS_ERROR, {
                        'message': 'Incomplete upload',
                        'bytes_received': bytes_received,
                        'resumable': True
                    })
                    send_message(self.client_socket, 'RESPONSE', response)
                    return
                calculated_hash = calculate_file_hash(upload_info['path'])
                if file_hash and calculated_hash != file_hash:
                    logger.warning(f"Checksum failed for resumed upload from {self.client_address}: {filename}")
                    response = create_response(STATUS_CHECKSUM_FAILED)
                    send_message(self.client_socket, 'RESPONSE', response)
                    return
                os.rename(upload_info['path'], upload_info['target_path'])
                with incomplete_uploads_lock:
                    if filename in incomplete_uploads:
                        del incomplete_uploads[filename]
                elapsed_time = time.time() - start_time
                transfer_rate = (file_size - upload_info['bytes_received']) / (1024 * 1024 * elapsed_time) if elapsed_time > 0 else 0
                logger.info(f"Resumed upload complete from {self.client_address}: {filename} ({file_size} bytes, {transfer_rate:.2f} MB/s)")
                response = create_response(STATUS_OK, {
                    'message': 'Upload successful',
                    'filename': os.path.basename(upload_info['target_path']),
                    'size': file_size,
                    'hash': calculated_hash
                })
                send_message(self.client_socket, 'RESPONSE', response)
        except Exception as e:
            logger.error(f"Error during resumed upload from {self.client_address}: {str(e)}")
            response = create_response(STATUS_ERROR, {'message': str(e)})
            send_message(self.client_socket, 'RESPONSE', response)
    def handle_download(self, data):
        """Sends requested files to clients"""
        filename = data.get('filename')
        start_byte = data.get('start_byte', 0)  
        if not filename:
            response = create_response(STATUS_ERROR, {'message': 'Missing filename'})
            send_message(self.client_socket, 'RESPONSE', response)
            return
        file_path = os.path.join(SHARED_FILES_DIR, filename)
        if not os.path.exists(file_path):
            logger.warning(f"File not found for download request from {self.client_address}: {filename}")
            response = create_response(STATUS_FILE_NOT_FOUND)
            send_message(self.client_socket, 'RESPONSE', response)
            return
        file_size = get_file_size(file_path)
        file_hash = calculate_file_hash(file_path)
        response = create_response(STATUS_OK, {
            'filename': filename,
            'file_size': file_size,
            'file_hash': file_hash,
            'start_byte': start_byte
        })
        send_message(self.client_socket, 'RESPONSE', response)
        message = receive_message(self.client_socket)
        if not message or message.get('command') != 'DOWNLOAD_CONFIRM':
            logger.warning(f"Client {self.client_address} did not confirm download for {filename}")
            return
        try:
            with open(file_path, 'rb') as f:
                if start_byte > 0:
                    f.seek(start_byte)
                bytes_sent = start_byte
                start_time = time.time()
                while bytes_sent < file_size:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    self.client_socket.sendall(chunk)
                    bytes_sent += len(chunk)
                elapsed_time = time.time() - start_time
                transfer_rate = (file_size - start_byte) / (1024 * 1024 * elapsed_time) if elapsed_time > 0 else 0
                logger.info(f"Download complete for {self.client_address}: {filename} ({file_size} bytes, {transfer_rate:.2f} MB/s)")
        except Exception as e:
            logger.error(f"Error during download for {self.client_address}: {str(e)}")
    def handle_list(self):
        """Provides clients with a list of available files"""
        try:
            files = []
            for filename in os.listdir(SHARED_FILES_DIR):
                file_path = os.path.join(SHARED_FILES_DIR, filename)
                if os.path.isfile(file_path) and not filename.endswith('.part'):
                    files.append({
                        'name': filename,
                        'size': get_file_size(file_path),
                        'modified': os.path.getmtime(file_path)
                    })
            response = create_response(STATUS_OK, {'files': files})
            send_message(self.client_socket, 'RESPONSE', response)
            logger.info(f"Sent file list to {self.client_address} ({len(files)} files)")
        except Exception as e:
            logger.error(f"Error listing files for {self.client_address}: {str(e)}")
            response = create_response(STATUS_ERROR, {'message': str(e)})
            send_message(self.client_socket, 'RESPONSE', response)
def start_server():
    """Initializes and runs the file sharing server"""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logger.info(f"Server started on {HOST}:{PORT}")
        print(f"Server started on {HOST}:{PORT}")
        while True:
            client_socket, client_address = server_socket.accept()
            client_handler = ClientHandler(client_socket, client_address)
            client_handler.start()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
        print("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        print(f"Server error: {str(e)}")
    finally:
        if 'server_socket' in locals():
            server_socket.close()
if __name__ == "__main__":
    start_server() 