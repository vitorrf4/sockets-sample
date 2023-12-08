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

#define LOCATION "localhost"
#define PORT "3003"  // the port users will be connecting to
#define BACKLOG 10	 // how many pending connections queue will hold

void sigchld_handler(int s)
{
	(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// verify endpoint connection and set address info
struct addrinfo* checkserver(char* server, char* port) {
	struct addrinfo *servinfo, hints;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(server, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	return servinfo;
}

// create socket and bind it to a particular service 
int bindsocket(struct addrinfo *servinfo) {
	struct addrinfo *p;
	int sockfd;
	int yes = 1;

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		// create the connection socket
		if ((sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		// verify if port is already in use
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		// bind endpoint to newly created socket
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
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

char* getclientinput(int new_fd) {
    int max_input_size = 30 * sizeof(char);
    char buffer[max_input_size];
    int data_size;

    send(new_fd, "Input your name: ", 17, 0);
    data_size = recv(new_fd, buffer, max_input_size, 0);

    // data_size will have a minimum of two bytes from recv()
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

void requesthandler(int sockfd, struct sockaddr_storage client_addr) {
	int sin_size, new_fd;
	char client_ip[INET6_ADDRSTRLEN];

	sin_size = sizeof client_addr;
	// deal with the connection request
	new_fd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);
	if (new_fd == -1) {
		perror("accept");
		return;
	}

	// get ip from incoming connection
	inet_ntop(client_addr.ss_family,
		get_in_addr((struct sockaddr *)&client_addr),
		client_ip, sizeof client_ip);
	printf("Server: got connection from %s\n", client_ip);
	
	char *buffer = getclientinput(new_fd);

	if (!fork() && buffer != NULL) { // this is the child process
		close(sockfd); // child doesn't need the listener

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

	close(new_fd);  // parent doesn't need this
}

int main(void) {
	int sockfd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo *servinfo;
	struct sockaddr_storage client_addr; // connector's address information
	struct sigaction sa;

	servinfo = checkserver(LOCATION, PORT);
	sockfd = bindsocket(servinfo);

	// listen to incoming requests on the socket
	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections on %s:%s...\n", LOCATION, PORT);

	while(1) {  // main accept() loop
		requesthandler(sockfd, client_addr);
	}

	return 0;
}