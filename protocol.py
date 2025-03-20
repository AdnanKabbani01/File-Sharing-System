import json
import struct
HEADER_SIZE = 8  
CHUNK_SIZE = 8192  
ENCODING = 'utf-8'  
CMD_UPLOAD = 'UPLOAD'
CMD_DOWNLOAD = 'DOWNLOAD'
CMD_LIST = 'LIST'
CMD_AUTH = 'AUTH'
CMD_RESUME = 'RESUME'
STATUS_OK = 'OK'
STATUS_ERROR = 'ERROR'
STATUS_AUTH_REQUIRED = 'AUTH_REQUIRED'
STATUS_AUTH_SUCCESS = 'AUTH_SUCCESS'
STATUS_AUTH_FAILED = 'AUTH_FAILED'
STATUS_FILE_NOT_FOUND = 'FILE_NOT_FOUND'
STATUS_CHECKSUM_FAILED = 'CHECKSUM_FAILED'
def create_message(command, data=None):
    
    if data is None:
        data = {}
    message = {
        'command': command,
        'data': data
    }
    json_message = json.dumps(message).encode(ENCODING)
    header = struct.pack('!Q', len(json_message))
    return header + json_message
def parse_message(message_bytes):
    
    message_str = message_bytes.decode(ENCODING)
    message = json.loads(message_str)
    return message
def receive_message(sock):
    
    header = sock.recv(HEADER_SIZE)
    if not header or len(header) < HEADER_SIZE:
        return None
    message_length = struct.unpack('!Q', header)[0]
    chunks = []
    bytes_received = 0
    while bytes_received < message_length:
        chunk = sock.recv(min(message_length - bytes_received, CHUNK_SIZE))
        if not chunk:
            return None
        chunks.append(chunk)
        bytes_received += len(chunk)
    message_bytes = b''.join(chunks)
    return parse_message(message_bytes)
def send_message(sock, command, data=None):
    
    message = create_message(command, data)
    try:
        sock.sendall(message)
        return True
    except Exception:
        return False
def create_response(status, data=None):
    
    if data is None:
        data = {}
    return {
        'status': status,
        'data': data
    } 