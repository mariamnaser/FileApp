# Multi-Mode File Sharing System

This Python script implements a Multi-Mode File Sharing System that allows both server and client functionalities for file sharing. The script uses threading and socket programming to enable communication between clients and the server. Below, you'll find an overview of the script's functionality and how to use it.


## Features
### Server Mode
In server mode (`-s`), the script acts as a file sharing server. It provides the following functionalities:

- Registers clients when they connect and updates the client table.
- Manages shared files and their availability.
- Handles registration, offer, and deregistration commands from clients.

### Client Mode
In client mode (`-c`), the script acts as a file sharing client. It provides the following functionalities:

- Registers with the server.
- Requests files from other clients.
- Lists available files for download.
- Offers files to other clients.
- Sets a shared directory for file sharing.

## Usage
### Server Mode
To run the script in server mode, use the following command:

```
python3 FileApp.py -s <port>
```
Replace **<port>** with the desired port number to start the server.


### Client Mode
To run the script in client mode, use the following command:

```
python3 FileApp.py -c <name> <server_ip> <server_port> <udp_port> <tcp_port>
```
- Replace **<name>** with your chosen client name
- Replace **<server_ip>** with the server's IP address,
- Replace **<server_port>** with the server's port number,
- Replace **<udp_port>** with the UDP port for this client,
- Replace **<tcp_port>** with the TCP port for this client.

## Client Commands
- `request <file> <client_name>`: Request a file from another client.
- `list`: List available files for download.
- `offer <file1> <file2> ...`: Offer files for sharing.
- `dereg`: Deregister from the server and exit.
- `setdir <directory_path>`: Set a shared directory for offering files.

## Note
- The script uses UDP(server) and TCP(clients) sockets for communication.
- Clients need to register with the server before using the system.
- Clients can offer files, request files from others, and list available files.
- Ensure that the shared directory is set using the `setdir` command before offering files.
