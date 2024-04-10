import os  # For file path operations
import socket  # For network connections
import threading  # For running tasks in parallel
import ssl  # For encrypted communication
import json  # For parsing configuration files
from prompt_toolkit import PromptSession  # For interactive command line prompts
from prompt_toolkit.shortcuts import clear  # For clearing the command line interface
import time  # For sleep functionality
from watchdog.observers import Observer  # For monitoring directory changes
from watchdog.events import (
    FileSystemEventHandler,
)  # For handling directory change events

# Load configuration for the client from a JSON file
with open("config.json", "r") as config_file:
    config = json.load(config_file)  # Parse the JSON configuration
    client_config = config["client"]  # Extract the client-specific configuration

# Assign configuration variables
HOST = client_config["server_host"]  # The server's hostname or IP address
PORT = client_config["server_port"]  # The server's port number
SHARED_FILES_DIR = client_config["shared_files_dir"]  # Directory for shared files
DOWNLOADS_DIR = client_config["downloads_dir"]  # Directory for downloaded files

listening_port = None  # To be dynamically determined based on available ports
listening_thread = None  # Thread for listening to incoming file requests
log_buffer = []  # Buffer for log messages to be displayed in the CLI
CHUNK_SIZE = 1024 * 1024  # Size in bytes for each chunk of a file during downloads
notify_server_socket = None  # Socket for notifying the server about file changes


def get_dynamic_chunk_size(total_size):
    """Determine the chunk size dynamically based on the total size of the file."""
    if total_size < 50 * 1024**2:  # smaller than 50MB
        return 512 * 1024  # 512KB
    elif total_size < 1 * 1024**3:  # smaller than 1GB
        return 1 * 1024**2  # 1MB
    elif total_size < 5 * 1024**3:  # smalled than 3GB
        return 10 * 1024**2  # 10MB
    else:
        return 20 * 1024**2


def find_available_port():
    """Find an available port dynamically and assign it to `listening_port`."""
    global listening_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp_sock:
        temp_sock.bind(("0.0.0.0", 0))  # Bind to an available port
        listening_port = temp_sock.getsockname()[1]  # Retrieve the assigned port


def initialize_listening():
    """Initialize a thread to listen for incoming file requests if not already running."""
    global listening_thread
    if not listening_thread or not listening_thread.is_alive():
        log("Initializing listening for incoming connections...")
        listening_thread = threading.Thread(
            target=listen_for_file_transfers, daemon=True
        )
        listening_thread.start()


def listen_for_file_transfers():
    """Set up a server socket to listen for and handle incoming file requests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ls:
        ls.bind(("0.0.0.0", listening_port))  # Listen on all network interfaces
        ls.listen()
        while True:
            conn, addr = ls.accept()  # Accept incoming connections
            threading.Thread(
                target=handle_file_request, args=(conn, addr), daemon=True
            ).start()


def get_file_list():
    """Retrieve a list of file names from the shared files directory."""
    if not os.path.exists(SHARED_FILES_DIR):
        os.makedirs(SHARED_FILES_DIR)  # Ensure the directory exists
    return [
        f
        for f in os.listdir(SHARED_FILES_DIR)
        if os.path.isfile(os.path.join(SHARED_FILES_DIR, f))
    ]


def send_command(s, command):
    """Send a command to the server and return the response."""
    try:
        s.sendall(command.encode())  # Send the command
        response = s.recv(4096).decode()  # Wait for a response
        return response
    except Exception as e:
        log(f"Error sending command '{command}': {e}")
        return ""  # Return an empty string in case of an error


def download_chunk(args):
    host, port, filename, start_byte, end_byte, chunk_seq, total_chunks, chunk_size = (
        args
    )
    chunk_filename = os.path.join(DOWNLOADS_DIR, f"{filename}.part{chunk_seq}")

    # Ensure the directory for chunk files exists
    os.makedirs(os.path.dirname(chunk_filename), exist_ok=True)

    received_size = 0
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ds:
            ds.settimeout(15)
            ds.connect((host, int(port)))
            request_cmd = f"REQUEST_CHUNK {filename} {start_byte} {end_byte}"
            ds.sendall(request_cmd.encode())

            with open(chunk_filename, "wb") as f:
                while True:
                    data = ds.recv(
                        min(chunk_size, end_byte - start_byte + 1 - received_size)
                    )
                    if not data:
                        break
                    f.write(data)
                    received_size += len(data)

            if received_size == end_byte - start_byte + 1:
                log(f"Chunk {chunk_seq + 1} of {total_chunks} downloaded successfully.")
            else:
                log(
                    f"Chunk {chunk_seq + 1} of {total_chunks} partially downloaded. Expected {end_byte - start_byte + 1} bytes, received {received_size} bytes."
                )
                raise Exception("Incomplete chunk download")

    except Exception as e:
        log(f"Failed to download chunk {chunk_seq + 1}: {e}")
        if os.path.exists(chunk_filename):
            os.remove(chunk_filename)


def merge_chunks(filename, total_chunks):
    final_filepath = os.path.join(DOWNLOADS_DIR, filename)

    # Ensure the directory for the final file exists
    os.makedirs(os.path.dirname(final_filepath), exist_ok=True)

    with open(final_filepath, "wb") as final_file:
        for i in range(total_chunks):
            chunk_filename = os.path.join(DOWNLOADS_DIR, f"{filename}.part{i}")
            with open(chunk_filename, "rb") as chunk_file:
                final_file.write(chunk_file.read())
            os.remove(chunk_filename)

    log(f"File '{filename}' reassembled from {total_chunks} chunks.")


def download_file_in_chunks(peers, filename):
    """Coordinate the download of a file in chunks from multiple peers with dynamic chunk sizing."""
    start_time = time.time()  # Record the start time

    host, port = peers[0].split(":")  # Assuming first peer can provide file size
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, int(port)))
        s.sendall(f"FILE_SIZE {filename}".encode())
        total_size = int(s.recv(1024).decode())

    chunk_size = get_dynamic_chunk_size(total_size)
    num_chunks = (total_size // chunk_size) + (1 if total_size % chunk_size > 0 else 0)

    log(
        f"Downloading '{filename}' in {num_chunks} chunks of size {chunk_size} bytes..."
    )

    threads = []
    for i in range(num_chunks):
        start_byte = i * chunk_size
        end_byte = min((i + 1) * chunk_size - 1, total_size - 1)
        peer = peers[i % len(peers)]
        host, port = peer.split(":")
        args = (host, port, filename, start_byte, end_byte, i, num_chunks, chunk_size)
        thread = threading.Thread(target=download_chunk, args=(args,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    merge_chunks(filename, num_chunks)
    end_time = time.time()  # Record the end time after the download completes

    total_time = end_time - start_time  # Calculate the total time taken
    log(f"Successfully downloaded and merged '{filename}' in {total_time:.2f} seconds.")


def list_files_and_download(session, s, option):
    """Display a list of available files and handle file download requests."""
    response = send_command(s, "LIST")  # Request the list of available files
    if response.strip():  # Check if the response is not empty
        if option == "2":  # If the user wants to view the files
            log("\nList of peers and their shared files:")
            for line in response.strip().split("\n"):
                log(line)
        elif option == "3":  # If the user wants to download a file
            files_set = set()
            for line in response.strip().split("\n"):
                parts = line.split("Files: ")
                if len(parts) > 1:
                    file_names = parts[1].strip()
                    files_set.update(
                        [
                            f.strip()
                            for f in file_names.split(",")
                            if not f.strip().isdigit()
                        ]
                    )
            log("\nAvailable files to download:")
            for file in sorted(files_set):
                log(file)
            filename = session.prompt("\nEnter the filename to download: ").strip()
            response = send_command(s, f"DOWNLOAD {filename}")
            if response and "File not found." not in response:
                peers = response.split(";")
                download_file_in_chunks(peers, filename)
            else:
                log("\nFile not found or no peers available.")
    else:
        log("\nNo files available for download.")


def handle_file_request(conn, addr):
    """Handle incoming file requests from peers, sending requested file chunks."""
    try:
        data = conn.recv(1024).decode()  # Receive the request command
        command, *args = data.split()
        if command == "REQUEST_CHUNK":
            filename, start_byte, end_byte = args  # Parse the chunk request arguments
            send_file_chunk(
                conn, filename, int(start_byte), int(end_byte)
            )  # Send the requested file chunk
        elif command == "FILE_SIZE":
            filename = args[0]  # Parse the file size request argument
            send_file_size(conn, filename)  # Send the size of the requested file
    except Exception as e:
        log(f"Error handling request from {addr}: {e}")
    finally:
        conn.close()  # Close the connection after handling the request


def send_file_size(conn, filename):
    """Send the size of a requested file to the requesting peer."""
    filepath = os.path.join(SHARED_FILES_DIR, filename)  # Construct the file path
    if not os.path.exists(filepath):
        conn.sendall(
            "ERROR: File not found.".encode()
        )  # Send an error if the file does not exist
        return
    file_size = os.path.getsize(filepath)  # Get the size of the file
    conn.sendall(str(file_size).encode())  # Send the file size
    log(
        f"Sent file size {file_size} for '{filename}' to {conn.getpeername()}"
    )  # Log the action


def send_file_chunk(conn, filename, start_byte, end_byte):
    """Send a requested chunk of a file to the requesting peer."""
    filepath = os.path.join(SHARED_FILES_DIR, filename)  # Construct the file path
    if not os.path.exists(filepath):
        conn.sendall(
            "ERROR: File not found.".encode()
        )  # Send an error if the file does not exist
        return
    with open(filepath, "rb") as f:
        f.seek(start_byte)  # Seek to the start byte of the requested chunk
        chunk = f.read(end_byte - start_byte + 1)  # Read the chunk
        conn.sendall(chunk)  # Send the chunk
    log(f"Sent chunk of '{filename}' ({start_byte}-{end_byte}) to {conn.getpeername()}")


def send_file_chunk(conn, filename, start_byte, end_byte):
    """Send a requested chunk of a file to a peer."""
    filepath = os.path.join(SHARED_FILES_DIR, filename)
    if not os.path.exists(filepath):
        conn.sendall("ERROR: File not found.".encode())
        return
    with open(filepath, "rb") as f:
        f.seek(start_byte)
        # Continue sending file chunk
        chunk = f.read(end_byte - start_byte + 1)
        conn.sendall(chunk)
    log(f"Sent chunk of '{filename}' ({start_byte}-{end_byte}) to {conn.getpeername()}")


def log(message):
    """Log a message to the CLI."""
    log_buffer.append(message)
    refresh_cli()


def refresh_cli():
    """Refresh the CLI interface to display new messages."""
    clear()
    for log_entry in log_buffer:
        print(log_entry)
    print("\n" + "-" * 50)
    print("Client Menu:")
    print("1. Share Files")
    print("2. View Files")
    print("3. Download File")
    print("4. Exit")


def start_file_monitoring():
    """Start monitoring the shared files directory for changes."""
    observer = Observer()
    event_handler = FileChangeHandler()
    observer.schedule(event_handler, path=SHARED_FILES_DIR, recursive=True)
    observer.start()


class FileChangeHandler(FileSystemEventHandler):
    """Handle file system events in the shared files directory."""

    def on_any_event(self, event):
        if not event.is_directory:
            log(f"Detected change in shared files directory: {event.src_path}")
            notify_server()


def notify_server_setup():
    """Set up a secure connection to notify the server about file changes."""
    global notify_server_socket
    try:
        notify_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        notify_server_socket.connect((HOST, PORT))

        # Set up SSL context with relaxed security settings for development/testing
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Skip certificate verification

        # Wrap the socket with SSL context
        secure_sock = context.wrap_socket(notify_server_socket, server_hostname=HOST)
        log("Notification connection established.")
    except Exception as e:
        log(f"Error setting up notification connection: {e}")
        if notify_server_socket:
            notify_server_socket.close()
        notify_server_socket = None


def notify_server():
    global notify_server_socket
    if notify_server_socket is None:
        log("Notification connection not established. Attempting to set up...")
        try:
            base_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            base_socket.connect((HOST, PORT))

            # Set up SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Only for development/testing

            # Wrap the base socket with SSL
            notify_server_socket = context.wrap_socket(
                base_socket, server_hostname=HOST
            )
            log("Notification connection established.")
        except Exception as e:
            log(f"Error setting up notification connection: {e}")
            if base_socket:
                base_socket.close()
            return

    try:
        files = get_file_list()
        command = f"FILES_CHANGED {listening_port} " + " ".join(files)
        notify_server_socket.sendall(command.encode())  # Use the SSL-wrapped socket
        response = notify_server_socket.recv(4096).decode()
        log("Server notified about file changes: " + response)
    except Exception as e:
        log(f"Error notifying server: {e}")
        notify_server_socket.close()
        notify_server_socket = None  # Reset for reinitialization on next attempt


def client_cli():
    session = PromptSession()
    find_available_port()
    initialize_listening()
    start_file_monitoring()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # Create a new SSL context for client-side connections
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Wrap the socket with the client-side SSL context
        secure_sock = context.wrap_socket(s, server_hostname=HOST)

        refresh_cli()
        while True:
            choice = session.prompt("Choose an option: ").strip()
            if choice == "1":
                files = get_file_list()
                if files:
                    command = f"SHARE {listening_port} " + " ".join(files)
                    send_command(secure_sock, command)
                    log(f"Shared files: {', '.join(files)}")
                    initialize_listening()
                else:
                    log("No files to share.")
            elif choice == "2":
                list_files_and_download(session, secure_sock, "2")
            elif choice == "3":
                list_files_and_download(session, secure_sock, "3")
            elif choice == "4":
                log("Exiting...")
                break
            else:
                log("Invalid option. Please try again.")


if __name__ == "__main__":
    client_cli()
