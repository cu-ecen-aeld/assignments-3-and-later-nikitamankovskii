#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/select.h>

#define PORT         9000
#define BACKLOG      1
#define DATA_FILE    "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE  1024

volatile sig_atomic_t is_running = 1;

void signal_handler(int signo) {
    syslog(LOG_INFO, "Caught signal, exiting");
    is_running = 0;
}

int main(int argc, char *argv[]) {
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    int is_deemon = 0;

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        is_deemon = 1;
    }
    
    openlog("aesdsocket", LOG_PID, LOG_USER);    
    
    
    int sock_fd = -1;
    int client_fd = -1;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        syslog(LOG_ERR, "Socket creation failed: %s", strerror(errno));
        return -1;
    }
    
    struct sockaddr_in addr_server;
    memset(&addr_server, 0, sizeof(addr_server));
    
    addr_server.sin_family = AF_INET;
    addr_server.sin_addr.s_addr = htonl(INADDR_ANY);
    addr_server.sin_port = htons(PORT);
    
    if (bind(sock_fd, (struct sockaddr *)&addr_server, sizeof(addr_server)) != 0) {
        syslog(LOG_ERR, "Bind failed: %s", strerror(errno));
        goto cleanup;
    }
    

    struct sockaddr_in addr_client;
    char client_ip[INET_ADDRSTRLEN];
    socklen_t addr_client_len = sizeof(addr_client);
    char buffer[BUFFER_SIZE];
    ssize_t recv_bytes;
    FILE *fp = NULL;
    int result = -1;
    

    if (is_deemon) {
        pid_t pid = fork();
        if (pid < 0) exit(-1);
        if (pid > 0) exit(EXIT_SUCCESS);

        umask(0);
        setsid();

        if (chdir("/") < 0) exit(-1);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }    

    if (listen(sock_fd, BACKLOG) != 0) {
        syslog(LOG_ERR, "Listen failed: %s", strerror(errno));
        goto cleanup;
    }

    while (!is_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);

        int sel = select(sock_fd + 1, &read_fds, NULL, NULL, NULL);
        if (sel == -1) {
            if (errno == EINTR) break;
            syslog(LOG_ERR, "select failed: %s", strerror(errno));
            break;
        }
        
        if (FD_ISSET(sock_fd, &read_fds)) {
            client_fd = accept(sock_fd, (struct sockaddr *)&addr_client, &addr_client_len);
            if (client_fd == -1) {
                if (errno == EINTR) break;
                syslog(LOG_ERR, "Accept failed: %s", strerror(errno));
                continue;
            }

            inet_ntop(AF_INET, &addr_client.sin_addr, client_ip, sizeof(client_ip));
            syslog(LOG_INFO, "Accepted connection from %s", client_ip);

            fp = fopen(DATA_FILE, "a+");
            if (!fp) {
                syslog(LOG_ERR, "Failed to open file: %s", strerror(errno));
                close(client_fd);
                continue;
            }

            size_t total_len = 0;
            char *packet = NULL;

            while (!is_running && (recv_bytes = recv(client_fd, buffer, sizeof(buffer)-1, 0)) > 0) {
                buffer[recv_bytes] = '\0';
                char *nl_pos = strchr(buffer, '\n');
                if (!nl_pos) {
                    packet = realloc(packet, total_len + recv_bytes + 1);
                    if (!packet) {
                        syslog(LOG_ERR, "Memory reallocation failed");
                        break;
                    }
                    memcpy(packet + total_len, buffer, recv_bytes + 1);
                    total_len += recv_bytes;
                    continue;
                }

                // include the newline
                size_t chunk_len = nl_pos - buffer + 1;
                packet = realloc(packet, total_len + chunk_len + 1);
                if (!packet) {
                    syslog(LOG_ERR, "Memory allocation failed");
                    break;
                }
                memcpy(packet + total_len, buffer, chunk_len);
                total_len += chunk_len;
                packet[total_len] = '\0';

                fwrite(packet, 1, total_len, fp);
                fflush(fp);

                // Send full file content
                fseek(fp, 0, SEEK_SET);
                while (!feof(fp)) {
                    size_t read_len = fread(buffer, 1, sizeof(buffer), fp);
                    if (read_len > 0) send(client_fd, buffer, read_len, 0);
                }

                free(packet);
                packet = NULL;
                total_len = 0;
            }

            free(packet);
            fclose(fp);
            fp = NULL;

            syslog(LOG_INFO, "Closed connection from %s", client_ip);
            close(client_fd);
            client_fd = -1;
        }
    }

    result = 0;
    
cleanup:
    if (client_fd != -1) close(client_fd);
    if (sock_fd != -1) close(sock_fd);
    if (fp) fclose(fp);
    
    remove(DATA_FILE);
    
    closelog();
    
    return result;
}
