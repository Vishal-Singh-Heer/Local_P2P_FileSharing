---

# Peer-to-Peer File Sharing System

This Python-based file sharing system facilitates the sharing, listing, and downloading of files among clients in a peer-to-peer (P2P) network. It leverages socket programming for network communication, SSL for encryption, and multithreading for concurrent operations, ensuring secure and efficient file transfers.

## Architecture Overview

The system adopts a hybrid P2P architecture, where a central server is used for coordination while the file transfers occur directly between peers. This design minimizes the server's load and bandwidth usage, as it does not partake in actual file transfers. The server's primary role includes managing client connections, maintaining a list of shared files, and facilitating peer discovery. Once peers are aware of each other, large files can be transferred directly between them in chunks, enhancing scalability and performance.

## Features

- **SSL-Encrypted Communication:** Ensures all communications are secure.
- **Peer-to-Peer File Transfers:** Direct file transfers between clients to minimize server load.
- **Dynamic Chunk Sizing:** Optimizes file transfer speeds based on file size.
- **Concurrent Downloads:** Supports downloading different file chunks simultaneously.
- **File Change Monitoring:** Automatically updates file listings in response to changes in shared directories.

## Getting Started

### Prerequisites

- Python 3.6+
- OpenSSL (for generating SSL certificates)
- Required Python packages: `prompt_toolkit`, `watchdog`

Install the necessary Python packages using pip:

```bash
pip install prompt_toolkit watchdog
```

### Configuration

Edit the `config.json` file to specify the server and client settings:

```json
{
  "server": {
    "host": "YOUR_SERVER_HOST",
    "port": YOUR_SERVER_PORT,
    "certificate_path": "path/to/cert.pem",
    "key_path": "path/to/key.pem"
  },
  "client": {
    "server_host": "YOUR_SERVER_HOST",
    "server_port": YOUR_SERVER_PORT,
    "shared_files_dir": "path/to/shared/files",
    "downloads_dir": "path/to/downloads"
  }
}
```

### Generating a Self-Signed SSL Certificate for Testing

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

Update `config.json` with the paths to `cert.pem` and `key.pem`. Note: Use self-signed certificates only for testing.

### Running the Server

```bash
python server.py
```

### Running the Client

```bash
python client.py
```

Follow the CLI prompts to share files, view available files, and download files.

## Usage

- **Share Files:** Share the files in your configured `shared_files_dir`.
- **View Files:** List available files shared by connected peers.
- **Download Files:** Download a specific file by specifying its name.

## Contributing

Contributions are welcome! Feel free to fork the repo, make changes, and submit a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---
