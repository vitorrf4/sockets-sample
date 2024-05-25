#include "start_server.h"

#define LOCATION "localhost"
#define PORT "3000"

int main(void) {
	start_server(LOCATION, PORT, 0);

	return 0;
}