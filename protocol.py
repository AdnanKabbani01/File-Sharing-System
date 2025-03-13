import json
import struct

# Core protocol settings
HEADER_SIZE = 8  # Header size in bytes for message length
CHUNK_SIZE = 8192  # Chunk size for efficient file transfers
ENCODING = 'utf-8'  # Text encoding for messages

# Available commands
CMD_UPLOAD = 'UPLOAD'
CMD_DOWNLOAD = 'DOWNLOAD'
CMD_LIST = 'LIST'
CMD_AUTH = 'AUTH'
CMD_RESUME = 'RESUME'

# Response status codes
STATUS_OK = 'OK'
STATUS_ERROR = 'ERROR'
STATUS_AUTH_REQUIRED = 'AUTH_REQUIRED'
STATUS_AUTH_SUCCESS = 'AUTH_SUCCESS'
STATUS_AUTH_FAILED = 'AUTH_FAILED'
STATUS_FILE_NOT_FOUND = 'FILE_NOT_FOUND'
STATUS_CHECKSUM_FAILED = 'CHECKSUM_FAILED'

def create_message(command, data=None):
    """
    Creates a protocol-formatted message ready to be sent
    
    Args:
        command: The command type (UPLOAD, DOWNLOAD, etc.)
        data: Additional data for the command (optional)
        
    Returns:
        A binary message with header and JSON body
    """
    if data is None:
        data = {}
    
    message = {
        'command': command,
        'data': data
    }
    
    # Convert to JSON and encode as bytes
    json_message = json.dumps(message).encode(ENCODING)
    
    # Add length header for proper message framing
    header = struct.pack('!Q', len(json_message))
    
    return header + json_message

def parse_message(message_bytes):
    """
    Converts a received binary message back to a Python dictionary
    
    Args:
        message_bytes: The raw message bytes
        
    Returns:
        The parsed message as a dictionary
    """
    message_str = message_bytes.decode(ENCODING)
    message = json.loads(message_str)
    
    return message

def receive_message(sock):
    """
    Receives and reconstructs a complete message from a socket
    
    Args:
        sock: The socket to receive from
        
    Returns:
        The parsed message or None if connection closed
    """
    # First get the message length from the header
    header = sock.recv(HEADER_SIZE)
    if not header or len(header) < HEADER_SIZE:
        return None
    
    message_length = struct.unpack('!Q', header)[0]
    
    # Then receive the full message body in chunks
    chunks = []
    bytes_received = 0
    
    while bytes_received < message_length:
        chunk = sock.recv(min(message_length - bytes_received, CHUNK_SIZE))
        if not chunk:
            return None
        chunks.append(chunk)
        bytes_received += len(chunk)
    
    # Combine chunks and parse
    message_bytes = b''.join(chunks)
    return parse_message(message_bytes)

def send_message(sock, command, data=None):
    """
    Sends a message through a socket
    
    Args:
        sock: The socket to send through
        command: Command type
        data: Additional data for the command
        
    Returns:
        True if sent successfully, False on error
    """
    message = create_message(command, data)
    try:
        sock.sendall(message)
        return True
    except Exception:
        return False

def create_response(status, data=None):
    """
    Creates a standardized response message
    
    Args:
        status: Status code (OK, ERROR, etc.)
        data: Additional response data
        
    Returns:
        A formatted response dictionary
    """
    if data is None:
        data = {}
    
    return {
        'status': status,
        'data': data
    } 