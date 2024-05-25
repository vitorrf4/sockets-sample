#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include "start_server.h"

#define BACKLOG 10	 // How many pending connections queue will hold

// FUNCTIONS DECLARATIONS
void *get_in_addr(struct sockaddr *sa);
struct addrinfo* check_server(char* server, char* port);
int bind_socket(struct addrinfo *servinfo);
void sigchld_handler(int s);
char* get_client_input(int new_fd);
void request_handler(int sockfd, struct sockaddr_storage client_addr);
void create_daemon();
int start_server(char* address, char* port, int daemonize);

// FUNCTION IMPLEMENTATIONS

int start_server(char* address, char* port, int daemonize) {
	int sockfd;  // Listen on sock_fd, new connection on new_fd
	struct addrinfo *servinfo;
	struct sockaddr_storage client_addr; // Connector's address information
	struct sigaction sa;

	servinfo = check_server(address, port);
	sockfd = bind_socket(servinfo);

	// Listen to incoming requests on the socket
	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // Reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("Started Server\nWaiting for connections on %s:%s...\n", address, port);

	if (daemonize == 1) {
		printf("Daemonizing process...\n");
		create_daemon();
	}

	while(1) {  // Main accept() loop
		request_handler(sockfd, client_addr);
	}

	return 0;
}

// Verify endpoint connection and set address info
struct addrinfo* check_server(char* server, char* port) {
	struct addrinfo *servinfo, hints;
	int addrinfo_res;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	addrinfo_res = getaddrinfo(server, port, &hints, &servinfo);

	if (addrinfo_res != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(addrinfo_res));
		exit(1);
	}

	return servinfo;
}

// Create socket and bind it to a particular service 
int bind_socket(struct addrinfo *servinfo) {
	struct addrinfo *p;
	int sockfd;
	int yes = 1;

	// loop through all the results and bind to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next) {
		// create the connection socket
		if ((sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		// set options for the socket, allowing the socket to be reused immediately after the server exits
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		// bind endpoint to newly created socket
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			exit(1);
		}

		break;
	}
 
	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	return sockfd;
}

void sigchld_handler(int s) {
	(void)s; // Quiet unused variable warning

	// Waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}


void create_daemon() {
	// Change to the "/" directory
	int nochdir = 0;

	// Redirect standard input, output and error to /dev/null
	// This is equivalent to "closing the file descriptors"
	int noclose = 0;
	
	if (daemon(nochdir, noclose))
		perror("daemon");


	openlog("SERVER_DAEMON", LOG_PID, LOG_USER);
	syslog(LOG_USER | LOG_INFO, "starting");
}

void request_handler(int sockfd, struct sockaddr_storage client_addr) {
	int sin_size, new_fd;
	char client_ip[INET6_ADDRSTRLEN];

	sin_size = sizeof client_addr;
	// Deal with the connection request
	new_fd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);
	if (new_fd == -1) {
		perror("accept");
		return;
	}

	// Get ip from incoming connection
	inet_ntop(client_addr.ss_family,
		get_in_addr((struct sockaddr *)&client_addr),
		client_ip, sizeof client_ip);
	syslog(LOG_USER | LOG_INFO, "got connection from %s", client_ip);
	
	char *buffer = get_client_input(new_fd);

	if (!fork() && buffer != NULL) { // This is the child process
		close(sockfd); // Child doesn't need the listener

		int data_size = strlen(buffer);
		char msg[7 + data_size]; 
		snprintf(msg, sizeof msg, "Hello %s\n", buffer);

		if (send(new_fd, msg, sizeof(msg), 0) == -1) {
			perror("send");
		}

		if (data_size > 2) {
			free(buffer);
		}

		close(new_fd);
		exit(0);
	}

	close(new_fd);  // Parent doesn't need this
}

// Get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
	switch (sa->sa_family) {
		case AF_INET: return &(((struct sockaddr_in*)sa)->sin_addr);
		case AF_INET6: return &(((struct sockaddr_in6*)sa)->sin6_addr);
	}
}

char* get_client_input(int new_fd) {
    int max_input_size = 30 * sizeof(char);
    char buffer[max_input_size];
    int data_size;

    send(new_fd, "Input your name: ", 17, 0);
    data_size = recv(new_fd, buffer, max_input_size, 0);

    // Data_size will have a minimum of two bytes from recv()
    if (data_size <= 2) {
        return NULL;
    }

    printf("Received %d bytes of data\n", data_size);
    printf("Message: %.*s\n", data_size, buffer);

    char *input = (char *)calloc(data_size + 1, sizeof(char));
    strncpy(input, buffer, data_size - 2);
    input[data_size - 2] = '\n'; 

    return input;
}