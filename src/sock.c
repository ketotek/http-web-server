#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <string.h>

#include "util.h"

#define BACKLOG 10

int sock_create_listener(unsigned short port)
{
	struct sockaddr_in addr;
	int fd, rc, opt;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	ASSERT(fd > 0);
	
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	opt = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
	ASSERT(rc == 0);

	rc = bind(fd, (struct sockaddr*)&addr, sizeof addr);
	ASSERT(rc == 0);
	
	rc = listen(fd, BACKLOG);
	ASSERT(rc == 0);
	
	return fd;
}

int get_peer_address(int sockfd, char *buf, size_t len)
{
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);

        if (getpeername(sockfd, (struct sockaddr *) &addr, &addrlen) < 0)
                return -1;

        snprintf(buf, len, "%s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        return 0;
}

