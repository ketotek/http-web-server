#ifndef SOCK_H
#define SOCK_H

int sock_create_listener(unsigned short);
int get_peer_address(int sockfd, char *buf, size_t len);

#endif

