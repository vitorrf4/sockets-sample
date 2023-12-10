# C Socket Server
Sample C server made to studies sockets and low-level networking.

This server:
- Queries the information of an adress and/or a port with getaddrinfo()

- Creates a socket with the given address information

- Bind socket to address

- Listens for requests on the newly created socket

- Sets the server as a daemon process


When you call the server endpoint, a new socket in a child process is generated, sets the 
connection with the client, and asks for the client's name, and replies with a "Hello {inserted name}".