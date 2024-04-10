
---

# Peer-to-Peer File Sharing System

Welcome to the Peer-to-Peer File Sharing System, a Python-based platform designed to streamline the process of sharing, listing, and downloading files across a decentralized network. Utilizing the principles of socket programming, this system ensures secure and efficient file transfers through SSL encryption, while multithreading allows for simultaneous operations, enhancing the user experience in high-bandwidth peer-to-peer networks.

## Architecture Overview

At the heart of this system lies a hybrid P2P architecture. A central server plays a pivotal role in coordinating the network, managing client connections, and maintaining an updated list of available files. However, the heavy lifting of file transfer is handled directly between peers. This method significantly reduces server load and conserves bandwidth, as the server does not engage in the actual transfer of files. Large files are segmented into chunks for direct peer-to-peer transfer, optimizing both scalability and transfer efficiency.

## Key Features

- **Secure Communications:** Leveraging SSL encryption to secure all data exchanges within the network.
- **Direct Peer-to-Peer Transfers:** Facilitating file transfers directly between clients, enhancing efficiency.
- **Adaptive Chunk Sizing:** Dynamically adjusting chunk sizes for file transfers to optimize speed and reliability.
- **Simultaneous Downloads:** Enabling the concurrent downloading of multiple file segments.
- **Automated File Listing Updates:** Employing file change monitoring to keep the shared file list current and accurate.

## Getting Started

### Prerequisites

Ensure you have the following installed:
- Python 3.6 or later
- OpenSSL (for SSL certificate generation)
- Python packages: `prompt_toolkit`, `watchdog`

Install the necessary packages using pip:

```bash
pip install prompt_toolkit watchdog
```

### System Configuration

Modify `config.json` with your server and client details:

```json
{
  "server": {
    "host": "YOUR_SERVER_HOST",
    "port": YOUR_SERVER_PORT,
    "certificate_path": "path/to/your/certificate.pem",
    "key_path": "path/to/your/key.pem"
  },
  "client": {
    "server_host": "YOUR_SERVER_HOST",
    "server_port": YOUR_SERVER_PORT,
    "shared_files_directory": "path/to/your/shared_files",
    "downloads_directory": "path/to/your/downloads"
  }
}
```

### SSL Certificate Generation (for testing)

Generate a self-signed SSL certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

Update `config.json` with the paths to your newly generated `cert.pem` and `key.pem`. Note: Self-signed certificates are recommended only for testing purposes.

### Launch Instructions

**To start the server:**

```bash
python server.py
```

**To run a client instance:**

```bash
python client.py
```

Navigate through the CLI prompts to share, view, and download files within the network.

## Detailed Usage Guide

- **Sharing Files:** Place files in your configured `shared_files_directory` to share them with the network.
- **Listing Files:** View a list of files shared by peers connected to the network.
- **Downloading Files:** Select and download desired files from the list of available files.

## Contributing to the Project

We encourage contributions to improve this file-sharing system. Feel free to fork the repository, make your changes, and submit a pull request.

## Frequently Asked Questions (FAQ)

**Q: Can I use this system on any network?**  
A: Yes, the system is designed to work on any local network setup, provided the necessary ports are open and accessible.

**Q: Is it safe to use for sensitive files?**  
A: The system uses SSL encryption for all transfers, ensuring a high level of security. However, for extremely sensitive data, additional layers of security may be warranted.

## License

This project is open-sourced under the MIT License. For more details, see the LICENSE file in the repository.

--- 
