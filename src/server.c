
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <libaio.h>
#include <sys/capability.h>

#include "epoll.h"
#include "sock.h"
#include "util.h"
#include "http.h"

#define PORT 80
#define DOCUMENT_ROOT "./"
#define ADDR_BUFSIZ 64

static char *document_root;
static unsigned short server_port = PORT;

static int epollfd;
static int event_fd;
static int listener;
static io_context_t ctx;


enum connection_state {
    STATE_DATA_RECEIVED,
    STATE_DATA_SENT,
    STATE_CONNECTION_CLOSED
};
struct connection {
    int sockfd;
    /* buffers used for receiving messages and then echoing them back */
    char recv_buffer[BUFSIZ];
    size_t recv_len;
    char send_buffer[BUFSIZ];
    size_t send_len;
    enum connection_state state;

    http_parser_t parser;

    /* fd for the requested file */
    int localfd;

    char *req_file;
    char *params;

    struct iocb iocb;
    struct iocb *piocb;
    size_t bytes_sent;
    size_t bytes_read;
    size_t bytes_total;

    /* flag indicating the server is transfering a static file */
    int static_transf;
    /* flag indicating the server is running a process to send its output */
    int process_output;
};


static char http_response_fmt[BUFSIZ] = 
                    "HTTP/1.1 %d %s\r\n"
                    "Date: Sun, 08 May 2011 09:26:16 GMT\r\n"
                    "Server: Apache/2.2.9\r\n"
                    "Last-Modified: Mon, 02 Aug 2010 17:55:28 GMT\r\n"
                    "Accept-Ranges: bytes\r\n"
                    "Content-Length: %d\r\n"
                    "Vary: Accept-Encoding\r\n"
                    "Connection: close\r\n"
                    "Content-Type: text/html\r\n"
                    "\r\n";

static void finalize(struct connection *conn);

/* Creates an absolute file path for the given resource, based on the server root */
static char *make_file_path(char *root, char *resource)
{
    size_t nroot, nres;
    char *fp;

    nroot = strlen(root);
    nres = strlen(resource);

    fp = malloc(nroot + nres + 4);
    ASSERT(fp != NULL);

    strcpy(fp, root);

    /* Eliminate double '/' */
    if (root[nroot - 1] == '/' && resource[0] == '/') {
        strcat(fp, &resource[1]);
    } else {
        strcat(fp, resource);
    }

    return fp;
}

static char *get_document_root()
{
    if (!document_root)
        return DOCUMENT_ROOT;
    return document_root;
}

static void make_http_response(char *buffer, size_t code, size_t length)
{
    if (code == 200) {
        sprintf(buffer, http_response_fmt, code, "OK", length);
    }
    if (code == 404) {
        sprintf(buffer, http_response_fmt, code, "Not Found", 0);
    }
}

static int file_exists(char *filename)
{
    struct stat buffer;
    int status;

    status = lstat(filename, &buffer);
    return (status == 0);
}


static struct connection *connection_create(int sockfd)
{
    struct connection *conn = malloc(sizeof(*conn));
    ASSERT(conn != NULL);

    conn->sockfd = sockfd;
    memset(conn->recv_buffer, 0, BUFSIZ);
    memset(conn->send_buffer, 0, BUFSIZ);

    conn->static_transf = 0;
    conn->process_output = 0;

    return conn;
}

static void connection_copy_buffers(struct connection *conn)
{
    ASSERT(conn->send_len <= sizeof(conn->send_buffer));

    conn->send_len = conn->recv_len;
    memcpy(conn->send_buffer, conn->recv_buffer, conn->send_len);
}

static void connection_remove(struct connection *conn)
{
    close(conn->sockfd);
    conn->state = STATE_CONNECTION_CLOSED;
    http_parser_free(&conn->parser);
    free(conn);
}

static void handle_new_connection()
{
    static int sockfd;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    struct connection *conn;
    int rc;

    sockfd = accept(listener, (struct sockaddr*) &addr, &addrlen);
    ASSERT(sockfd >= 0);

    rc = fcntl(sockfd, F_SETFL, O_NONBLOCK);
    ASSERT(rc == 0);

    dprintf("Accepted connection from: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    conn = connection_create(sockfd);

    rc = http_epoll_add_ptr_in(epollfd, sockfd, conn);
    ASSERT(rc == 0);
}

/*
 * Receive message on socket.
 * Store message in recv_buffer in struct connection.
 */
static enum connection_state receive_message(struct connection *conn)
{
    ssize_t bytes_recv;
    int rc;
    char abuffer[ADDR_BUFSIZ];

    rc = get_peer_address(conn->sockfd, abuffer, ADDR_BUFSIZ);
    if (rc < 0) {
        perror("get_peer_address");
        goto remove_connection;
    }

    bytes_recv = recv(conn->sockfd, conn->recv_buffer, BUFSIZ, 0);
    if (bytes_recv < 0) {		/* error in communication */
        dlog(LOG_CRIT, "Error in communication from: %s\n", abuffer);
        goto remove_connection;
    }
    if (bytes_recv == 0) {		/* connection closed */
        dlog(LOG_INFO, "Connection closed from: %s\n", abuffer);
        goto remove_connection;
    }

    dlog(LOG_DEBUG, "Received message from: %s\n", abuffer);

    conn->recv_len = bytes_recv;
    conn->state = STATE_DATA_RECEIVED;

    return STATE_DATA_RECEIVED;

remove_connection:
    rc = http_epoll_remove_ptr(epollfd, conn->sockfd, conn);
    ASSERT(rc == 0);

    /* remove current connection */
    connection_remove(conn);

    return STATE_CONNECTION_CLOSED;
}

/*
 * Send message on socket.
 * Store message in send_buffer in struct connection.
 */
static ssize_t send_message(struct connection *conn)
{
    ssize_t bytes_sent;
    int rc;
    char abuffer[64];

    rc = get_peer_address(conn->sockfd, abuffer, 64);
    if (rc < 0) {
        perror("get_peer_address");
        goto remove_connection;
    }

    bytes_sent = send(conn->sockfd, conn->send_buffer, conn->send_len, 0);
    if (bytes_sent < 0) {		/* error in communication */
        dlog(LOG_CRIT, "Error in communication to %s\n", abuffer);
        goto remove_connection;
    }
    if (bytes_sent == 0) {		/* connection closed */
        dlog(LOG_INFO, "Connection closed to %s\n", abuffer);
        goto remove_connection;
    }

    /* all done - remove out notification */
    rc = http_epoll_update_ptr_in(epollfd, conn->sockfd, conn);
    ASSERT(rc == 0);

    conn->state = STATE_DATA_SENT;

    return bytes_sent;

remove_connection:
    rc = http_epoll_remove_ptr(epollfd, conn->sockfd, conn);
    ASSERT(rc == 0);

    /* remove current connection */
    connection_remove(conn);

    return 0;
}

static size_t file_size(char *filename)
{
    struct stat buffer;
    int status;

    status = stat(filename, &buffer);
    ASSERT(status == 0);

    dlog(LOG_INFO, "FileSize %s : %jd\n", filename, buffer.st_size);

    return buffer.st_size;
}

static void send_static_file(struct connection *conn, char *filename)
{
    int rc;

    conn->localfd = open(filename, O_RDONLY);
    ASSERT(conn->localfd > 0);

    conn->bytes_sent = sendfile(conn->sockfd, conn->localfd, 0, conn->bytes_total);
    ASSERT(conn->bytes_sent > 0);

    dlog(LOG_INFO, "First time sent %zd/%zd\n", conn->bytes_sent, conn->bytes_total);
    if (conn->bytes_sent < conn->bytes_total) {
        rc = http_epoll_update_ptr_out(epollfd, conn->sockfd, conn);
        ASSERT(rc == 0);
    } else {
        finalize(conn);
    }
}

static void send_dynamic_file(struct connection *conn, char *filename)
{
    int rc;

    memset(&conn->iocb, 0, sizeof(struct iocb));

    conn->piocb = &conn->iocb;

    conn->localfd = open(filename, O_RDONLY);
    ASSERT(conn->localfd > 0);

    conn->bytes_sent = 0;
    io_prep_pread(&conn->iocb, conn->localfd, conn->recv_buffer, 
            MIN(BUFSIZ, conn->bytes_total), 0);

    io_set_eventfd(&conn->iocb, event_fd);

    conn->iocb.data = (void*)conn;
    rc = io_submit(ctx, 1, &conn->piocb);
    ASSERT(rc > 0);
}

static void send_process_output(struct connection *conn, char *filename, char *params)
{
    int pid, p[2];
    int rc, status;
    char *args[3];

    rc = pipe(p);
    ASSERT(rc == 0);

    args[0] = filename;
    args[1] = params;
    args[2] = 0;

    pid = fork();
    if (pid) {
        close(p[1]);
        conn->recv_len = read(p[0], conn->recv_buffer, sizeof conn->recv_buffer);
        waitpid(pid, &status, 0);
        close(p[0]);

        dlog(LOG_INFO, "Read %d bytes from process\n", conn->recv_len);
    } else {
        close(p[0]);
        dup2(p[1], STDOUT_FILENO);
        execv(filename, args);
    }
}

static void handle_client_request(struct connection *conn)
{
    enum connection_state ret_state;
    http_request_t *req;
    char *req_file;

    ret_state = receive_message(conn);
    if (ret_state == STATE_CONNECTION_CLOSED)
        return;

    http_parser_init(&conn->parser);
    req = parse_http_request(&conn->parser, conn->recv_buffer, conn->recv_len);
    if (!req) {
        return;
    }
    dlog(LOG_INFO, "Parsed url: %s\n", req->path);
    dlog(LOG_INFO, "Parsed params: %s\n", req->params);

    req_file = make_file_path(get_document_root(), req->path);
    if (!file_exists(req_file) || strlen(req->path) == 1) {

        make_http_response(conn->send_buffer, 404, 0);
        conn->send_len = strlen(conn->send_buffer);
        send_message(conn);

        goto end;
    }
    /* Save file size for future use */
    conn->bytes_total = file_size(req_file);
    conn->bytes_read = 0;
    conn->bytes_sent = 0;
    if (strncmp(req->path, "/static", 7) == 0) {
        dlog(LOG_INFO, "Sending static file %s\n", req_file);
        make_http_response(conn->send_buffer, 200, conn->bytes_total);
        conn->send_len = strlen(conn->send_buffer);

        send_message(conn);

        conn->static_transf = 1;

        send_static_file(conn, req_file);

        goto end;
    }
    if (strncmp(req->path, "/cgi", 4) == 0) {

        dlog(LOG_INFO, "Sending CGI process output %s\n", req_file);
        send_process_output(conn, req_file, req->params);

        make_http_response(conn->send_buffer, 200, conn->recv_len);
        conn->send_len = strlen(conn->send_buffer);
        send_message(conn);

        conn->process_output = 1;
        conn->bytes_total = conn->recv_len;
        ASSERT(http_epoll_update_ptr_out(epollfd, conn->sockfd, conn) == 0);	

        goto end;
    }
    conn->static_transf = 0;
    dlog(LOG_INFO, "Sending dynamic file %s\n", req_file);
    make_http_response(conn->send_buffer, 200, conn->bytes_total);
    conn->send_len = strlen(conn->send_buffer);
    send_message(conn);

    send_dynamic_file(conn, req_file);

end:

    free(req_file);

    return;
}


static void complete_requests()
{
    int rc;
    u_int64_t efd_val;
    struct io_event *events;
    size_t i, n_ev;
    struct connection *conn;

    rc = read(event_fd, &efd_val, sizeof(efd_val));
    ASSERT(rc > 0);

    dlog(LOG_INFO, "%lu operations have completed\n", efd_val);

    events = malloc(efd_val * sizeof(struct io_event));
    ASSERT(events != NULL);

    rc = io_getevents(ctx, efd_val, /* min_nr */
            efd_val, /* max_nr */
            events,      /* vector to store completed events */
            NULL);        /* no timeout */

    ASSERT(rc >= 0);

    n_ev = rc;
    for (i = 0; i < n_ev; i++) {
        conn = (struct connection*)events[i].data;

        conn->recv_len = events[i].res;

        rc = http_epoll_update_ptr_out(epollfd, conn->sockfd, conn);
        ASSERT(rc == 0);

        dlog(LOG_INFO, "read file: %lu bytes\n", events[i].res);

        conn->bytes_read += events[i].res;
    }

    free(events);
}

static void finalize(struct connection *conn)
{
    int rc;

    rc = http_epoll_remove_ptr(epollfd, conn->sockfd, conn);
    ASSERT(rc == 0);

    if (conn->process_output != 1) {
        rc = close(conn->localfd);
        ASSERT(rc == 0);
    }
    /* remove current connection */
    connection_remove(conn);
}

static void next_data(struct connection *conn)
{
    int rc;
    size_t left;

    if (conn->static_transf == 1) {
        left = sendfile(conn->sockfd, conn->localfd, 0, 
                conn->bytes_total - conn->bytes_sent);
        ASSERT(left != -1);

        if (left <= 0) {

            finalize(conn);
            dlog(LOG_INFO, "done reading static\n");
            return;
        }

        conn->bytes_sent += left;
        dlog(LOG_INFO, "Sent next %zd bytes: %zd/%zd\n", left, conn->bytes_sent, conn->bytes_total);
        if (conn->bytes_sent < conn->bytes_total) {
            rc = http_epoll_update_ptr_out(epollfd, conn->sockfd, conn);
            ASSERT(rc == 0);
        }
    } else if (conn->process_output == 1) {
        ssize_t sent;

        connection_copy_buffers(conn);

        sent = send_message(conn);

        if (sent == 0)
            dlog(LOG_CRIT, "Sent 0 bytes\n");

        conn->bytes_sent += sent;
        if (conn->bytes_sent == conn->bytes_total) {
            finalize(conn);
            dlog(LOG_CRIT, "Process output sent\n");
        }
    } else {
        connection_copy_buffers(conn);

        left = conn->bytes_total - conn->bytes_read;
        if (left > 0) {
            memset(&conn->iocb, 0, sizeof(struct iocb));

            io_prep_pread(&conn->iocb, conn->localfd, conn->recv_buffer, 
                    MIN(left, BUFSIZ), conn->bytes_read);

            io_set_eventfd(&conn->iocb, event_fd);
            conn->iocb.data = (void*)conn;
            conn->piocb = &conn->iocb;

            rc = io_submit(ctx, 1, &conn->piocb);
            ASSERT(rc > 0);

            dlog(LOG_INFO, "continue reading\n");
        }

        send_message(conn);

        conn->bytes_sent += conn->send_len;
        if (conn->bytes_sent == conn->bytes_total) {
            finalize(conn);
            dlog(LOG_INFO, "done reading\n");
            return;
        }

    }
}

static void free_resources()
{
    if (document_root)
        free(document_root);

    close(listener);
    close(event_fd);
    close(epollfd);
}

static void print_usage(int argc, char *argv[])
{
    fprintf(stderr, "usage: %s [-r document_root] [-p port] [-h]\n", argv[0]);
    fprintf(stderr, "\t-r\t\tSet document root\n");
    fprintf(stderr, "\t-p\t\tSet server port number\n");
    fprintf(stderr, "\t-h\t\tDisplay this information\n");
}

static void parse_options(int argc, char *argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "r:p:h")) != -1) {
        switch (opt) {
            case 'r':
                document_root = strdup(optarg);
                break;
            case 'p':
                server_port = atoi(optarg);
                ASSERT(server_port > 0 && server_port < 65536);
                break;
            case 'h':
            default:
                print_usage(argc, argv);
                exit(EXIT_SUCCESS);
        }
    }
}

static int check_permissions()
{
    cap_t caps;
    cap_flag_value_t flag;
    int rc, ret;

    caps = cap_get_proc();
    rc = cap_get_flag(caps, CAP_NET_BIND_SERVICE, CAP_PERMITTED, &flag);
    ret = 0;
    if ((rc != 0 || flag != CAP_SET) && server_port < 1024) {
        ret = 1;
        fprintf(stderr, "CAP_NET_BIND_SERVICE capability missing, "
                "but required for using port number %d\n", server_port);
    }

    cap_free(caps);

    return ret;
}

int main(int argc, char *argv[])
{
    struct epoll_event rev;
    int rc;

    if (getuid() == 0) {
        fprintf(stderr, "You should not run this as root!\n");
        exit(EXIT_FAILURE);
    }

    parse_options(argc, argv);

    if (check_permissions())
        exit(EXIT_FAILURE);

    epollfd = http_epoll_create();
    ASSERT(epollfd > 0);

    event_fd = eventfd(0, 0);
    ASSERT(event_fd > 0);

    listener = sock_create_listener(server_port);

    rc = http_epoll_add_fd_in(epollfd, listener);
    ASSERT(rc == 0);

    rc = http_epoll_add_fd_in(epollfd, event_fd);
    ASSERT(rc == 0);

    rc = io_setup(10, &ctx);
    ASSERT(rc == 0);

    while (1) {
        /* wait for events */
        rc = http_epoll_wait_event(epollfd, &rev);
        ASSERT(rc >= 0);

        if (rev.data.fd == listener) {
            if (rev.events & EPOLLIN)
                handle_new_connection();
        }
        else 
            if (rev.data.fd == event_fd) {
                complete_requests();
            } else {
                if (rev.events & EPOLLIN) {
                    handle_client_request(rev.data.ptr);
                }
                if (rev.events & EPOLLOUT) {

                    next_data(rev.data.ptr);
                }
            }
    }

    free_resources();

    return 0;
}

/* vim: set ts=4 sw=4 tw=80 et :*/

