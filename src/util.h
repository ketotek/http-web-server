#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H

#include <stdlib.h>
#include <stdio.h>

#define MIN(a, b) ( (a) < (b) ? (a) : (b) )

#define ASSERT(cond) do {                                          \
	if (!(cond))     {                                         \
		fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);    \
		perror("");                                        \
		exit(EXIT_FAILURE);                                \
	}                                                          \
} while (0)

enum {
	LOG_CRIT,
	LOG_INFO,
	LOG_DEBUG
};

#ifndef LOG_LEVEL
#define LOG_LEVEL	LOG_DEBUG
#endif

#if defined DEBUG
#define dprintf(format, ...)					\
	fprintf(stderr, " [%s(), %s:%u] " format,		\
			__FUNCTION__, __FILE__, __LINE__,	\
			##__VA_ARGS__)
#else
#define dprintf(format, ...)					\
	do {							\
	} while (0)
#endif

#if defined DEBUG
#define dlog(level, format, ...)				\
	do {							\
		if (level <= LOG_LEVEL)				\
			dprintf(format, ##__VA_ARGS__);		\
	} while (0)
#else
#define dlog(level, format, ...)				\
	do {							\
	} while (0)
#endif



#endif

