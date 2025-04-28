import os
import socket
import sys
import time
import json
import argparse
from tqdm import tqdm

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import setup_logger, calculate_file_hash, get_file_size
from protocol import (
    receive_message, send_message, create_response,
    CMD_UPLOAD, CMD_DOWNLOAD, CMD_LIST, CMD_AUTH, CMD_RESUME,
    STATUS_OK, STATUS_ERROR, STATUS_AUTH_REQUIRED, STATUS_AUTH_SUCCESS, 
    STATUS_AUTH_FAILED, STATUS_FILE_NOT_FOUND, STATUS_CHECKSUM_FAILED,
    CHUNK_SIZE
)

DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 9000
DOWNLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads')
INCOMPLETE_DIR = os.path.join(DOWNLOAD_DIR, 'incomplete')
os.makedirs(DOWNLOAD_DIR, exist_ok=True)
os.makedirs(INCOMPLETE_DIR, exist_ok=True)
logger = setup_logger('client', 'logs/client.log')

class FileClient:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.socket = None
        self.authenticated = False
        self.role = None
    
    def connect(self):
        """Connect to the file server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            logger.info(f"Connected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
            print(f"Error connecting to server: {str(e)}")
            return False
    
    def disconnect(self):
        """Disconnect from the file server"""
        if self.socket:
            self.socket.close()
            self.socket = None
            logger.info("Disconnected from server")
    
    def authenticate(self, username, password):
        """Authenticate with the server"""
        if not self.socket:
            print("Not connected to server")
            return False
        
        data = {
            'username': username,
            'password': password
        }
        send_message(self.socket, CMD_AUTH, data)
        
        response = receive_message(self.socket)
        if not response:
            logger.error("No response from server during authentication")
            return False
        
        # Log the full response to debug
        logger.info(f"Received authentication response: {response}")
        
        # Fix: Get status from the correct location in the response
        if response.get('command') == 'RESPONSE':
            response_data = response.get('data', {})
            status = response_data.get('status')
            
            if status == STATUS_AUTH_SUCCESS:
                self.authenticated = True
                self.role = response_data.get('data', {}).get('role')
                logger.info(f"Authentication successful. Role: {self.role}")
                return True
            else:
                logger.warning(f"Authentication failed with status: {status}")
                return False
        else:
            logger.warning(f"Unexpected response format: {response}")
            return False
    
    def list_files(self):
        """List files available on the server"""
        if not self.socket:
            print("Not connected to server")
            return None
        
        send_message(self.socket, CMD_LIST)
        
        response = receive_message(self.socket)
        if not response:
            logger.error("No response from server during list files")
            return None
        
        if response.get('command') == 'RESPONSE':
            response_data = response.get('data', {})
            status = response_data.get('status')
            
            if status == STATUS_OK:
                files = response_data.get('data', {}).get('files', [])
                logger.info(f"Received file list from server ({len(files)} files)")
                return files
            elif status == STATUS_AUTH_REQUIRED:
                logger.warning("Authentication required")
                print("Authentication required. Please login first.")
                return None
            else:
                error_msg = response_data.get('data', {}).get('message', 'Unknown error')
                logger.error(f"Error listing files: {error_msg}")
                print(f"Error: {error_msg}")
                return None
        else:
            logger.error(f"Unexpected response format: {response}")
            return None
    
    def upload_file(self, file_path, overwrite=False):
        """Upload a file to the server"""
        if not self.socket:
            print("Not connected to server")
            return False
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            print(f"Error: File not found: {file_path}")
            return False
        
        filename = os.path.basename(file_path)
        file_size = get_file_size(file_path)
        file_hash = calculate_file_hash(file_path)
        
        data = {
            'filename': filename,
            'file_size': file_size,
            'file_hash': file_hash,
            'overwrite': overwrite
        }
        send_message(self.socket, CMD_UPLOAD, data)
        
        response = receive_message(self.socket)
        if not response:
            logger.error("No response from server during upload")
            return False
        
        if response.get('command') == 'RESPONSE':
            response_data = response.get('data', {})
            status = response_data.get('status')
            
            if status == STATUS_AUTH_REQUIRED:
                logger.warning("Authentication required")
                print("Authentication required. Please login first.")
                return False
            elif status != STATUS_OK:
                error_msg = response_data.get('data', {}).get('message', 'Unknown error')
                logger.error(f"Error uploading file: {error_msg}")
                print(f"Error: {error_msg}")
                return False
            
            try:
                with open(file_path, 'rb') as f:
                    bytes_sent = 0
                    start_time = time.time()
                    
                    with tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Uploading {filename}") as pbar:
                        while bytes_sent < file_size:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk:
                                break

                            self.socket.sendall(chunk)
                            bytes_sent += len(chunk)
                            pbar.update(len(chunk))
                
                response = receive_message(self.socket)
                if not response:
                    logger.error("No response from server after upload")
                    return False
                
                if response.get('command') == 'RESPONSE':
                    response_data = response.get('data', {})
                    status = response_data.get('status')
                    
                    if status == STATUS_OK:
                        elapsed_time = time.time() - start_time
                        transfer_rate = file_size / (1024 * 1024 * elapsed_time) if elapsed_time > 0 else 0
                        
                        logger.info(f"Upload successful: {filename} ({file_size} bytes, {transfer_rate:.2f} MB/s)")
                        print(f"Upload successful: {filename}")
                        print(f"Size: {file_size} bytes")
                        print(f"Transfer rate: {transfer_rate:.2f} MB/s")
                        return True
                    elif status == STATUS_CHECKSUM_FAILED:
                        logger.error(f"Upload failed: Checksum verification failed for {filename}")
                        print(f"Error: Checksum verification failed for {filename}")
                        return False
                    else:
                        error_msg = response_data.get('data', {}).get('message', 'Unknown error')
                        logger.error(f"Upload failed: {error_msg}")
                        print(f"Error: {error_msg}")
                        
                        if response_data.get('data', {}).get('resumable'):
                            bytes_received = response_data.get('data', {}).get('bytes_received', 0)
                            print(f"Upload is resumable. {bytes_received}/{file_size} bytes transferred.")
                        
                        return False
                else:
                    logger.error(f"Unexpected response format: {response}")
                    return False
            
            except Exception as e:
                logger.error(f"Error during file upload: {str(e)}")
                print(f"Error during file upload: {str(e)}")
                return False
        else:
            logger.error(f"Unexpected response format: {response}")
            return False
    
    def resume_upload(self, file_path):
        """Resume an interrupted file upload"""
        if not self.socket:
            print("Not connected to server")
            return False
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            print(f"Error: File not found: {file_path}")
            return False
        
        filename = os.path.basename(file_path)
        file_size = get_file_size(file_path)
        file_hash = calculate_file_hash(file_path)
        
        data = {
            'filename': filename,
            'file_hash': file_hash
        }
        send_message(self.socket, CMD_RESUME, data)
        response = receive_message(self.socket)
        if not response:
            logger.error("No response from server during resume upload")
            return False
        
        if response.get('command') == 'RESPONSE':
            response_data = response.get('data', {})
            status = response_data.get('status')
            
            if status == STATUS_AUTH_REQUIRED:
                logger.warning("Authentication required")
                print("Authentication required. Please login first.")
                return False
            elif status != STATUS_OK:
                error_msg = response_data.get('data', {}).get('message', 'Unknown error')
                logger.error(f"Error resuming upload: {error_msg}")
                print(f"Error: {error_msg}")
                return False
            
            bytes_received = response_data.get('data', {}).get('bytes_received', 0)
            try:
                with open(file_path, 'rb') as f:
                    # Seek to the position where we left off
                    f.seek(bytes_received)
                    
                    bytes_sent = bytes_received
                    start_time = time.time()
                    with tqdm(total=file_size, initial=bytes_received, unit='B', unit_scale=True, desc=f"Resuming upload of {filename}") as pbar:
                        while bytes_sent < file_size:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk:
                                break

                            self.socket.sendall(chunk)
                            bytes_sent += len(chunk)
                            pbar.update(len(chunk))

                response = receive_message(self.socket)
                if not response:
                    logger.error("No response from server after resumed upload")
                    return False
                
                if response.get('command') == 'RESPONSE':
                    response_data = response.get('data', {})
                    status = response_data.get('status')
                    
                    if status == STATUS_OK:
                        elapsed_time = time.time() - start_time
                        transfer_rate = (file_size - bytes_received) / (1024 * 1024 * elapsed_time) if elapsed_time > 0 else 0
                        
                        logger.info(f"Resumed upload successful: {filename} ({file_size} bytes, {transfer_rate:.2f} MB/s)")
                        print(f"Resumed upload successful: {filename}")
                        print(f"Size: {file_size} bytes")
                        print(f"Transfer rate: {transfer_rate:.2f} MB/s")
                        return True
                    elif status == STATUS_CHECKSUM_FAILED:
                        logger.error(f"Resumed upload failed: Checksum verification failed for {filename}")
                        print(f"Error: Checksum verification failed for {filename}")
                        return False
                    else:
                        error_msg = response_data.get('data', {}).get('message', 'Unknown error')
                        logger.error(f"Resumed upload failed: {error_msg}")
                        print(f"Error: {error_msg}")
                        return False
                else:
                    logger.error(f"Unexpected response format: {response}")
                    return False
            
            except Exception as e:
                logger.error(f"Error during resumed file upload: {str(e)}")
                print(f"Error during resumed file upload: {str(e)}")
                return False
        else:
            logger.error(f"Unexpected response format: {response}")
            return False
    
    def download_file(self, filename, resume=False):
        """Download a file from the server"""
        if not self.socket:
            print("Not connected to server")
            return False
        
        incomplete_path = os.path.join(INCOMPLETE_DIR, f"{filename}.part")
        target_path = os.path.join(DOWNLOAD_DIR, filename)
        
        start_byte = 0
        if resume and os.path.exists(incomplete_path):
            start_byte = os.path.getsize(incomplete_path)
            logger.info(f"Resuming download of {filename} from byte {start_byte}")

        data = {
            'filename': filename,
            'start_byte': start_byte
        }
        send_message(self.socket, CMD_DOWNLOAD, data)
        
        response = receive_message(self.socket)
        if not response:
            logger.error("No response from server during download")
            return False
        
        if response.get('command') == 'RESPONSE':
            response_data = response.get('data', {})
            status = response_data.get('status')
            
            if status == STATUS_AUTH_REQUIRED:
                logger.warning("Authentication required")
                print("Authentication required. Please login first.")
                return False
            elif status == STATUS_FILE_NOT_FOUND:
                logger.error(f"File not found on server: {filename}")
                print(f"Error: File not found on server: {filename}")
                return False
            elif status != STATUS_OK:
                error_msg = response_data.get('data', {}).get('message', 'Unknown error')
                logger.error(f"Error downloading file: {error_msg}")
                print(f"Error: {error_msg}")
                return False

            file_size = response_data.get('data', {}).get('file_size')
            file_hash = response_data.get('data', {}).get('file_hash')
            
            if file_size is None:
                logger.error("Missing file size in server response")
                print("Error: Missing file size in server response")
                return False

            send_message(self.socket, 'DOWNLOAD_CONFIRM')

            try:
                mode = 'ab' if resume and start_byte > 0 else 'wb'
                with open(incomplete_path, mode) as f:
                    bytes_received = start_byte
                    start_time = time.time()

                    with tqdm(total=file_size, initial=start_byte, unit='B', unit_scale=True, desc=f"Downloading {filename}") as pbar:
                        while bytes_received < file_size:
                            chunk = self.socket.recv(min(CHUNK_SIZE, file_size - bytes_received))
                            if not chunk:
                                break
                            
                            f.write(chunk)
                            bytes_received += len(chunk)
                            pbar.update(len(chunk))

                if bytes_received < file_size:
                    logger.warning(f"Incomplete download: {filename} ({bytes_received}/{file_size} bytes)")
                    print(f"Download incomplete. Received {bytes_received}/{file_size} bytes.")
                    print(f"You can resume the download later with: --resume {filename}")
                    return False
                calculated_hash = calculate_file_hash(incomplete_path)
                if file_hash and calculated_hash != file_hash:
                    logger.error(f"Checksum verification failed for {filename}")
                    print(f"Error: Checksum verification failed for {filename}")
                    return False
                os.rename(incomplete_path, target_path)
                elapsed_time = time.time() - start_time
                transfer_rate = (file_size - start_byte) / (1024 * 1024 * elapsed_time) if elapsed_time > 0 else 0
                
                logger.info(f"Download successful: {filename} ({file_size} bytes, {transfer_rate:.2f} MB/s)")
                print(f"Download successful: {filename}")
                print(f"Saved to: {target_path}")
                print(f"Size: {file_size} bytes")
                print(f"Transfer rate: {transfer_rate:.2f} MB/s")
                return True
            
            except Exception as e:
                logger.error(f"Error during file download: {str(e)}")
                print(f"Error during file download: {str(e)}")
                return False
        else:
            logger.error(f"Unexpected response format: {response}")
            return False

def print_file_list(files):
    """Print a formatted list of files"""
    if not files:
        print("No files available")
        return
    
    print("\nAvailable Files:")
    print("-" * 80)
    print(f"{'Filename':<40} {'Size':<15} {'Modified':<20}")
    print("-" * 80)
    
    for file in files:
        name = file.get('name', 'Unknown')
        size = file.get('size', 0)
        modified = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file.get('modified', 0)))

        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size/1024:.2f} KB"
        else:
            size_str = f"{size/(1024*1024):.2f} MB"
        
        print(f"{name:<40} {size_str:<15} {modified:<20}")
    
    print("-" * 80)

def main():
    """Main function to handle command line arguments"""
    parser = argparse.ArgumentParser(description='File Sharing Client')
    parser.add_argument('--host', default=DEFAULT_HOST, help='Server hostname or IP address')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Server port')
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    login_parser = subparsers.add_parser('login', help='Login to the server')
    login_parser.add_argument('username', help='Username')
    login_parser.add_argument('password', help='Password')
    
    subparsers.add_parser('list', help='List available files')

    upload_parser = subparsers.add_parser('upload', help='Upload a file')
    upload_parser.add_argument('file', help='File to upload')
    upload_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing file')

    resume_parser = subparsers.add_parser('resume', help='Resume an interrupted upload')
    resume_parser.add_argument('file', help='File to resume uploading')

    download_parser = subparsers.add_parser('download', help='Download a file')
    download_parser.add_argument('file', help='File to download')
    download_parser.add_argument('--resume', action='store_true', help='Resume an interrupted download')
    
    args = parser.parse_args()
    
    client = FileClient(args.host, args.port)
    if not client.connect():
        return
    
    try:
        if args.command == 'login':
            if client.authenticate(args.username, args.password):
                print(f"Login successful. Role: {client.role}")
            else:
                print("Login failed")
        
        elif args.command == 'list':
            files = client.list_files()
            if files is not None:
                print_file_list(files)
        
        elif args.command == 'upload':
            client.upload_file(args.file, args.overwrite)
        
        elif args.command == 'resume':
            client.resume_upload(args.file)
        
        elif args.command == 'download':
            client.download_file(args.file, args.resume)
        
        else:
            parser.print_help()
    
    finally:
        # Disconnect from server
        client.disconnect()

if __name__ == "__main__":
    main() 