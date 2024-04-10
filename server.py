# Import necessary libraries
import socket  # For network connections
import threading  # For concurrent execution
import logging  # For logging messages
import ssl  # For encrypted communication
import json  # For reading the configuration file

# Load server configuration from a JSON file
with open("config.json", "r") as config_file:
    config = json.load(config_file)  # Parse the JSON file
    server_config = config["server"]  # Extract the server configuration

# Assign configuration values to variables
HOST = server_config["host"]  # The server's host name or IP address
PORT = server_config["port"]  # The port number to listen on
CERTIFICATE_PATH = server_config["certificate_path"]  # Path to the SSL certificate
KEY_PATH = server_config["key_path"]  # Path to the SSL private key

# Initialize logging with a specified format
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)  # Get a logger for this module

# Dictionary to store client file information
files_dict = {}

# A thread lock to prevent concurrent access to shared resources
lock = threading.Lock()


def is_valid_filename(filename):
    """Check if a filename is valid by ensuring it does not contain forbidden characters."""
    forbidden_chars = '\\/:*?"<>|'
    return not any(c in filename for c in forbidden_chars) and filename != ""


def handle_client(conn, addr):
    """Handle each client connection in a separate thread."""
    client_id = addr  # Use the client's address as a unique identifier
    logger.info(f"Connected to client: {client_id}")

    try:
        while True:
            data = conn.recv(1024).decode()  # Receive data from the client
            if not data:
                # If no data is received, log a warning and break the loop to close the connection
                logger.warning(f"No data from {client_id}. Closing connection.")
                break

            # Parse the command and its arguments from the received data
            command, *args = data.split()

            # Execute different actions based on the command
            if command == "LIST":
                # Send a formatted list of files available for download
                response = format_file_list()
                conn.sendall(response.encode())
            elif command == "SHARE":
                # Update the shared files from a client
                with lock:
                    # Validate file names to ensure they are safe to use
                    valid_files = [f for f in args if is_valid_filename(f)]
                    # Update the global dictionary with the client's shared files
                    files_dict[addr] = (addr[0], int(args[0]), valid_files)
                logger.info(f"Client {addr} shared files: {valid_files}")
                conn.sendall("Files shared successfully".encode())
            elif command == "DOWNLOAD":
                # Provide a list of clients that have the requested file
                filename = args[0]
                response = get_clients_with_file(filename)
                conn.sendall(response.encode())
            elif command == "FILES_CHANGED":
                # Handle notification from clients about changes in their shared files
                handle_files_changed(conn, addr, args)
            else:
                # Respond to unrecognized commands with an error message
                conn.sendall(f"ERROR: Unknown command '{command}'".encode())
    except Exception as e:
        # Log any exceptions that occur while handling the client
        logger.error(f"Error with client {client_id}: {e}")
    finally:
        # Clean up and close the connection when done
        with lock:
            if client_id in files_dict:
                # Remove the client from the global dictionary
                del files_dict[client_id]
                logger.info(f"Client {client_id} has been removed from the peer list.")
        conn.close()  # Close the client connection
        logger.info(f"Disconnected from client: {client_id}")


def format_file_list():
    """Generate a formatted string of all files available for download."""
    with lock:
        # Use a lock to prevent concurrent modification of the `files_dict`
        file_list = [
            f"Client {client_addr}: IP: {ip}, Port: {port}, Files: {', '.join(files)}"
            for client_addr, (ip, port, files) in files_dict.items()
        ]
    return "\n".join(file_list)  # Return the formatted file list as a single string


def get_clients_with_file(filename):
    """Return a semicolon-separated list of clients that have the specified file."""
    with lock:
        # Find clients that have the requested file
        clients = [
            f"{ip}:{port}"
            for _, (ip, port, files) in files_dict.items()
            if filename in files
        ]
    return ";".join(clients) if clients else "File not found."


def handle_files_changed(conn, addr, args):
    """Update the file list for a client when notified of changes."""
    with lock:
        updated_files = args[1:]  # Extract the updated list of files from arguments
        if addr in files_dict:
            # If the client is already known, update their file list
            existing_entry = files_dict[addr]
            files_dict[addr] = (existing_entry[0], existing_entry[1], updated_files)
            logger.info(f"Updated file list for client {addr}: {updated_files}")
        else:
            # If it's a new client, add them to the dictionary
            files_dict[addr] = (addr[0], int(args[0]), updated_files)
            logger.info(f"Added new client {addr} with files: {updated_files}")
    conn.sendall("File list updated successfully.".encode())  # Acknowledge the update


def start_server():
    """Initialize and start the SSL-secured file sharing server."""
    server_sock = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    )  # Create a socket object
    server_sock.bind((HOST, PORT))  # Bind the socket to the host and port
    server_sock.listen(5)  # Listen for up to 5 connections

    # Set up SSL context for secure communication
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        certfile=CERTIFICATE_PATH, keyfile=KEY_PATH
    )  # Load SSL certificate and key

    ip = socket.gethostbyname(socket.gethostname())  # Fetch the server's IP address
    logger.info(f"Server IP Address: {ip} - Clients should use this IP to connect.")
    logger.info("Server is up and running. Waiting for secure connections...")

    try:
        while True:
            # Accept new connections
            client_socket, addr = server_sock.accept()
            secure_conn = context.wrap_socket(
                client_socket, server_side=True
            )  # Secure the connection with SSL
            # Handle each client connection in a new thread
            threading.Thread(target=handle_client, args=(secure_conn, addr)).start()
    except KeyboardInterrupt:
        # Gracefully shut down the server on a keyboard interrupt (Ctrl+C)
        logger.info("Server is shutting down.")
    except Exception as e:
        # Log any unexpected errors
        logger.error(f"An unexpected error occurred: {e}")
    finally:
        server_sock.close()  # Close the server socket when done


if __name__ == "__main__":
    start_server()  # Start the server if the script is run directly
