# Advanced File Sharing System

A secure, multithreaded client-server file sharing system that allows users to upload, download, and list files in a distributed environment with advanced features like authentication, integrity verification, and resumable transfers.

## Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [Starting the Servers](#starting-the-servers)
  - [Command-Line Interface](#command-line-interface)
  - [Web Interface](#web-interface)
- [Custom Protocol](#custom-protocol)
- [Security Features](#security-features)
- [Reliability Features](#reliability-features)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Future Enhancements](#future-enhancements)

## Features

### Core Features
- **Client-Server Architecture** with multithreading support for multiple simultaneous connections
- **File Operations**: Upload, download, and list files with detailed metadata
- **Custom TCP Socket-based Protocol** for efficient and reliable file transfers
- **File Integrity Checking** using SHA-256 hashing to prevent corruption
- **File Duplicate Management** with automatic versioning (filename_v2.txt, etc.)
- **Comprehensive Logging System** for both server and client activities

### Advanced Features
- **Web Interface** using Flask with a modern, responsive Bootstrap design
- **User Authentication and Access Control** with admin/user roles
- **Resumable Uploads and Downloads** with checkpointing for interrupted transfers
- **Progress Tracking** with real-time progress bars (CLI and web)
- **File Metadata** including size, modification time, and checksums

## System Architecture

The system consists of three main components:

1. **Socket Server** (`server/server.py`): 
   - Handles direct TCP connections for file transfers
   - Manages authentication and access control
   - Processes file operations (upload, download, list)
   - Maintains file integrity and versioning

2. **Web Server** (`server/web_server.py`):
   - Provides a user-friendly web interface
   - Handles file uploads through HTTP
   - Manages user authentication and session control
   - Offers admin features (user management, logs)

3. **Command-Line Client** (`client/client.py`):
   - Connects to the socket server for file operations
   - Provides a command-line interface for scripting and automation
   - Supports resumable transfers and progress tracking

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/file-sharing-system.git
   cd file-sharing-system
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

   Key dependencies:
   - socket (built-in)
   - threading (built-in)
   - hashlib (built-in)
   - logging (built-in)
   - tqdm==4.66.1 (for progress bars)
   - flask==2.3.3 (for web interface)
   - werkzeug==2.3.7 (for secure file handling)
   - flask-login==0.6.2 (for user authentication)

3. Create required directories (if not using the provided setup):
   ```
   mkdir -p server client logs shared_files
   ```

## Usage

### Starting the Servers

1. **Start the Socket Server**:
   ```
   python server/server.py
   ```
   The server will start on port 9000 by default.

2. **Start the Web Server** (optional, for web interface):
   ```
   python server/web_server.py
   ```
   The web server will start on port 5000 by default.

### Command-Line Interface

The command-line client provides the following commands:

1. **Authentication**:
   ```
   python client/client.py login <username> <password>
   ```
   Default credentials: admin / admin123

2. **List Files**:
   ```
   python client/client.py list
   ```

3. **Upload File**:
   ```
   python client/client.py upload <file_path>
   ```
   With overwrite option:
   ```
   python client/client.py upload <file_path> --overwrite
   ```

4. **Download File**:
   ```
   python client/client.py download <filename>
   ```

5. **Resume Upload** (for interrupted uploads):
   ```
   python client/client.py resume <file_path>
   ```

6. **Resume Download** (for interrupted downloads):
   ```
   python client/client.py download <filename> --resume
   ```

7. **Specify Server** (optional):
   ```
   python client/client.py --host <hostname> --port <port> <command>
   ```

### Web Interface

Access the web interface by navigating to `http://localhost:5000` in your browser.

1. **Login**: Use the login form with default credentials (admin/admin123)

2. **File Management**:
   - View all files with size and modification time
   - Download files with a single click
   - Upload files with progress tracking
   - Delete files (admin only)

3. **User Management** (admin only):
   - View all users and their roles
   - Add new users with specified roles
   - Delete existing users

4. **System Logs** (admin only):
   - View server, web server, and database logs
   - Filter logs by type
   - Auto-refresh logs

## Custom Protocol

The system uses a custom TCP-based protocol for client-server communication:

### Message Format
- **Header**: 8-byte length prefix (using `struct.pack`)
- **Body**: JSON-encoded message with command and data

### Commands
- `AUTH`: Authenticate with username and password
- `UPLOAD`: Upload a file with metadata
- `DOWNLOAD`: Request a file download
- `LIST`: Request a list of available files
- `RESUME`: Resume an interrupted upload

### Status Codes
- `OK`: Operation successful
- `ERROR`: Operation failed
- `AUTH_REQUIRED`: Authentication required
- `AUTH_SUCCESS`: Authentication successful
- `AUTH_FAILED`: Authentication failed
- `FILE_NOT_FOUND`: Requested file not found
- `CHECKSUM_FAILED`: File integrity check failed

### Example Protocol Flow (Upload)
1. Client sends: `{"command": "UPLOAD", "data": {"filename": "example.txt", "file_size": 1024, "file_hash": "abc123..."}}`
2. Server responds: `{"status": "OK", "data": {"ready": true, "temp_id": "example.txt"}}`
3. Client sends file data in chunks
4. Server responds: `{"status": "OK", "data": {"message": "Upload successful", "filename": "example.txt", "size": 1024, "hash": "abc123..."}}`

## Security Features

1. **Authentication**:
   - Username/password verification
   - Password hashing using SHA-256
   - Session-based authentication in web interface

2. **Access Control**:
   - Role-based permissions (admin vs. regular users)
   - Admin-only operations (delete files, manage users, view logs)

3. **File Security**:
   - Integrity verification using SHA-256 hashing
   - Secure filename handling to prevent path traversal
   - Temporary file storage during transfers

4. **Web Security**:
   - CSRF protection in web forms
   - Secure cookie handling
   - Input validation and sanitization

## Reliability Features

1. **File Integrity**:
   - SHA-256 hash verification before and after transfer
   - Automatic rejection of corrupted files

2. **Resumable Transfers**:
   - Server tracks partial uploads with byte position
   - Clients can resume from last successful byte
   - Temporary files for in-progress transfers

3. **Error Handling**:
   - Comprehensive error detection and reporting
   - Graceful handling of network interruptions
   - Detailed logging for troubleshooting

4. **Concurrency**:
   - Multithreaded server handles multiple clients
   - Thread-safe operations with proper locking
   - Connection pooling and resource management

## Project Structure

```
.
├── client/                 # Client-side code
│   ├── client.py           # Command-line client
│   └── downloads/          # Downloaded files directory
│       └── incomplete/     # Partially downloaded files
├── server/                 # Server-side code
│   ├── server.py           # Socket server implementation
│   ├── web_server.py       # Web interface server
│   ├── templates/          # HTML templates for web interface
│   └── static/             # Static assets for web interface
│       └── css/            # CSS stylesheets
├── shared_files/           # Server's file storage
│   └── temp/               # Temporary storage for uploads
├── logs/                   # Log files directory
├── utils.py                # Utility functions
├── protocol.py             # Protocol definitions
├── database.py             # User database management
├── requirements.txt        # Project dependencies
└── README.md               # Project documentation
```

## Configuration

### Server Configuration

Key configuration variables in `server/server.py`:
```python
HOST = '0.0.0.0'            
PORT = 9000                 
SHARED_FILES_DIR = '...'    
REQUIRE_AUTH = True         
```

Key configuration variables in `server/web_server.py`:
```python
HOST = '0.0.0.0'            
PORT = 5000                 
MAX_CONTENT_LENGTH = 1GB    
```

### Client Configuration

Key configuration variables in `client/client.py`:
```python
DEFAULT_HOST = 'localhost'  
DEFAULT_PORT = 9000        
DOWNLOAD_DIR = '...'       
```

### Protocol Configuration

Key configuration variables in `protocol.py`:
```python
HEADER_SIZE = 8             
CHUNK_SIZE = 8192           
ENCODING = 'utf-8'          
```

## Troubleshooting

### Common Issues

1. **Connection Refused**:
   - Ensure the server is running
   - Check if the port is blocked by a firewall
   - Verify the correct hostname/IP and port

2. **Authentication Failed**:
   - Verify username and password
   - Check if authentication is enabled on the server
   - Ensure the user database file is accessible

3. **File Transfer Errors**:
   - Check disk space on both client and server
   - Verify file permissions
   - Look for network interruptions in logs

4. **Web Interface Issues**:
   - Clear browser cache
   - Check browser console for JavaScript errors
   - Verify Flask dependencies are installed

### Logging

Logs are stored in the `logs/` directory:
- `server.log`: Socket server logs
- `web_server.log`: Web server logs
- `database.log`: User database logs
- `client.log`: Client-side logs

Enable debug logging by modifying the log level in `utils.py`:
```python
setup_logger('server', 'logs/server.log', level=logging.DEBUG)
```

## Future Enhancements

Potential improvements for future versions:

1. **Security Enhancements**:
   - TLS encryption for socket connections
   - Two-factor authentication
   - File encryption at rest

2. **Performance Improvements**:
   - Asynchronous I/O for better scalability
   - Connection pooling
   - Caching frequently accessed files

3. **Feature Additions**:
   - File sharing with access links
   - Directory support and recursive transfers
   - File synchronization capabilities
   - Search functionality

4. **UI Improvements**:
   - Mobile-responsive design
   - Drag-and-drop uploads
   - Real-time notifications


## Default Credentials

- Username: `admin`
- Password: `admin123`