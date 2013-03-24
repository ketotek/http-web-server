
#ifndef HTTP_EPOLL
#define HTTP_EPOLL

#include <sys/epoll.h>

#define EPOLL_TIMEOUT -1

static inline int http_epoll_create()
{
	return epoll_create(1);
}

static inline int http_epoll_add_fd_in(int epollfd, int fd)
{
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.fd = fd
	};

	return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
}

static inline int http_epoll_add_ptr_in(int epollfd, int fd, void *ptr)
{
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.ptr = ptr
	};

	return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
}

static inline int http_epoll_add_ptr_out(int epollfd, int fd, void *ptr)
{
	struct epoll_event ev = {
		.events = EPOLLOUT,
		.data.ptr = ptr
	};

	return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
}

static inline int http_epoll_update_ptr_out(int epollfd, int fd, void *ptr)
{
	struct epoll_event ev = {
		.events = EPOLLOUT,
		.data.ptr = ptr
	};

	return epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev);
}

static inline int http_epoll_update_ptr_in(int epollfd, int fd, void *ptr)
{
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.ptr = ptr
	};

	return epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev);
}

static inline int http_epoll_remove_ptr(int epollfd, int fd, void *ptr)
{
	return epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
}

static inline int http_epoll_wait_event(int epollfd, struct epoll_event *event)
{
	return epoll_wait(epollfd, event, 1, -1);
}

#endif

