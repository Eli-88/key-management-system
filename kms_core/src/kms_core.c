#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static struct sockaddr_in convert_ipv4(const char* host, short port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
    return addr;
}

int set_socket_option(int fd, int level, int option_name, int flag) {return setsockopt(fd, level, option_name, &flag, sizeof(flag));}
int tcp_socket() {return socket(AF_INET, SOCK_STREAM, 0);}
int tcp_listen(int fd, int backlog) {return listen(fd, backlog);}
int tcp_recv(int fd, void* buffer, int len) {return recv(fd, buffer, len , MSG_NOSIGNAL);}
int tcp_send(int fd, const void* buffer, int len) {return send(fd, buffer, len, MSG_NOSIGNAL);}
int tcp_close(int fd) {return close(fd);}
int tcp_shutdown(int fd) {return shutdown(fd, SHUT_RDWR);}

int tcp_accept_with_remote_address(int fd, char* remote_host, unsigned short remote_host_input_len, unsigned short* remote_port, unsigned short* remote_host_output_len)
{
    struct sockaddr_in remote_addr;
    socklen_t addr_len = sizeof(remote_addr);
    memset(&remote_addr, 0, addr_len);
    int conn = accept(fd, (struct sockaddr*)&remote_addr, &addr_len);

    if(remote_host != NULL && remote_port != NULL && remote_host_output_len != NULL)
    {
        inet_ntop(AF_INET, &remote_addr.sin_addr, remote_host, remote_host_input_len);
        unsigned output_len = strlen(remote_host);
        *remote_host_output_len = output_len;
        *remote_port = ntohs(remote_addr.sin_port);
    }

    return conn;
}
int tcp_accept(int fd) {return tcp_accept_with_remote_address(fd, NULL, 0, NULL, NULL);}

int tcp_connect(int fd, const char* host, short port) {
    struct sockaddr_in addr = convert_ipv4(host, port);
    return connect(fd, (struct sockaddr*) &addr, sizeof(addr));
}

int tcp_bind(int fd, const char* host, short host_len, short port)
{
    short max_len = MIN(host_len + 1, 16);
    char sanitized_host[max_len];
    memcpy(sanitized_host, host, host_len);
    sanitized_host[host_len] = '\0';

    struct sockaddr_in addr = convert_ipv4(sanitized_host, port);
    return bind(fd, (struct sockaddr*) &addr, sizeof(addr));
}

void* memory_map(void* address, size_t size, int prot, int flags, int fd, long offset) {return mmap(address, size, prot, flags, fd, offset);}
int memory_unmap(void* address, size_t size) {return munmap(address, size);}
