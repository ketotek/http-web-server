http-web-server
===============

This is a simple asynchronous (epoll-based) HTTP web server.
It uses a minimal HTTP request parser as described by RFC2616.

Features:
* Asynchronous I/O with epoll and libaio for disk access.
* Sending static files from "<rootdir>/static" using sendfile().
* Running programs/scripts in "<rootdir>/cgi" and sending the output like CGI.
* Good security policies:
  * Not running under "root"
  * Not needing to be setuid
  * Uses capabilities for binding() ports < 1024

Usage:
```
$ src/server -h
usage: src/server [-r document_root] [-p port] [-h]
        -r              Set document root
        -p              Set server port number
        -h              Display this information

$ src/server -r www -p 80
```
