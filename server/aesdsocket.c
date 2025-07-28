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
#include <sys/queue.h>
#include <pthread.h>
#include <time.h>

#define PORT         9000
#define BACKLOG      10
#define DATA_FILE    "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE  1024

volatile sig_atomic_t is_running = 1;

timer_t timer_id;

SLIST_HEAD(thread_list, thread_data) head;

pthread_mutex_t file_mutex;

typedef struct thread_data {
    pthread_t thread_id;
    SLIST_ENTRY(thread_data) entries;
} thread_data_t;


void *connection_handler(void *arg) {
    int tdata = *(int*)arg;
    free(arg);

    char client_ip[INET_ADDRSTRLEN];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    getpeername(tdata, (struct sockaddr *)&client_addr, &client_len);
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);

    int fp = open(DATA_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
    if(fp){
        syslog(LOG_INFO, "Opened file for writing data");
    } else {
        syslog(LOG_ERR, "Client failed to open file.");
        close (tdata);
        return NULL;
    }

    char buffer[BUFFER_SIZE];

    ssize_t bytes_read;
    pthread_mutex_lock(&file_mutex);
    while ((bytes_read = recv(tdata, buffer, BUFFER_SIZE, 0)) > 0) {
        
        if (write(fp, buffer, bytes_read) != bytes_read) {
            syslog(LOG_ERR, "Failed to write received data to file: %s", strerror(errno));
            pthread_mutex_unlock(&file_mutex);
            break;
        } else {
            syslog(LOG_INFO, "Read %ld bytes", bytes_read);
        }
        
        if (buffer[bytes_read - 1] == '\n') {
            break;
        }
    }
    pthread_mutex_unlock(&file_mutex);
    fsync(fp);
    close(fp);
    
    if (bytes_read < 0) {
        syslog(LOG_ERR, "Failed to receive data: %s, recv returned: %zd", strerror(errno), bytes_read);
    }
    FILE *filehandle = fopen(DATA_FILE, "r");
    if (filehandle == NULL) {
        syslog(LOG_ERR, "Failed to open file for reading: %s", strerror(errno));
        close(tdata);
        return NULL;
    }
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, filehandle)) > 0) {
        if (send(tdata, buffer, bytes_read, 0) < 0) {
            syslog(LOG_ERR, "Failed to send data to client: %s", strerror(errno));
            break;
        }
    }
    close(fp);
    close(tdata);

    
    syslog(LOG_INFO, "Closed connection to %s", client_ip);
    return NULL;

}

void timer_handler(union sigval dum_val) {
    (void)dum_val; 
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now); 
    char timestamp[100];
    int size = strftime(timestamp, sizeof(timestamp), "timestamp:%Y-%m-%d %H:%M:%S\n", tm_info);
    int file_fd = open(DATA_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (file_fd < 0) {
        syslog(LOG_ERR, "Failed opening file for writing timestamp");
        exit(EXIT_FAILURE);
    }
    pthread_mutex_lock(&file_mutex);
    if(write(file_fd, timestamp, size)){
        syslog(LOG_ERR, "Error writing timer to file: %s", strerror(errno));
    }
    pthread_mutex_unlock(&file_mutex);
}

void setup_timer() {
    struct sigevent sev;
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = timer_handler;
    sev.sigev_notify_attributes = NULL;
    if (timer_create(CLOCK_REALTIME, &sev, &timer_id) == -1) {
        syslog(LOG_ERR, "Failed to create timer: %s", strerror(errno));
        exit(1);
    }
    struct itimerspec timer_def;
    timer_def.it_value.tv_sec = 10;
    timer_def.it_value.tv_nsec = 0;
    timer_def.it_interval.tv_sec = 10;
    timer_def.it_interval.tv_nsec = 0;
    if (timer_settime(timer_id, 0, &timer_def, NULL) == -1) {
        syslog(LOG_ERR, "Failed to set timer: %s", strerror(errno));
        exit(1);
    }
}

int server_fd = -1;
int client_fd = -1;

void cleanup(){
    struct thread_data *entry;
    SLIST_FOREACH(entry, &head, entries) {
        pthread_cancel(entry->thread_id);
    }
    SLIST_FOREACH(entry, &head, entries) {
        pthread_join(entry->thread_id, NULL);
    }
    while (!SLIST_EMPTY(&head)) {
        entry = SLIST_FIRST(&head);
        SLIST_REMOVE_HEAD(&head, entries);
        free(entry);
    }
    if (server_fd >= 0) {
        close(server_fd);
        syslog(LOG_INFO, "Socket_fd terminated");
    }
    if (remove(DATA_FILE) != 0) {
        syslog(LOG_ERR, "Failed to delete the file %s: %s", DATA_FILE, strerror(errno));
    }
    pthread_mutex_destroy(&file_mutex); 
    syslog(LOG_INFO, "Sockets terminated");
    syslog(LOG_INFO, "Program acheived a graceful exit!!");
    
    closelog();
    
    close(client_fd);
    close(server_fd);
    exit(0);
}

void signal_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        syslog(LOG_INFO, "Caught signal, exiting");
        is_running = 0;
        cleanup();
    }
}


int main(int argc, char *argv[]) {
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    int is_deemon = 0;

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        is_deemon = 1;
    }
    
    openlog("aesdsocket", LOG_PID, LOG_USER);    

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        syslog(LOG_ERR, "Socket creation failed: %s", strerror(errno));
        return -1;
    }
    
    struct sockaddr_in addr_server;
    memset(&addr_server, 0, sizeof(addr_server));
    
    addr_server.sin_family = AF_INET;
    addr_server.sin_addr.s_addr = htonl(INADDR_ANY);
    addr_server.sin_port = htons(PORT);
    int __optval = 1;
    
    setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR, &__optval,sizeof(int));
    if (bind(server_fd, (struct sockaddr *)&addr_server, sizeof(addr_server)) != 0) {
        syslog(LOG_ERR, "Bind failed: %s", strerror(errno));
        cleanup();
    }
    
    syslog(LOG_INFO, "created socket: %d ID", server_fd);

    struct sockaddr_in addr_client;
    socklen_t addr_client_len = sizeof(addr_client);
    

    if (is_deemon) {
        pid_t pid = fork();
        if (pid < 0) exit(-1);
        if (pid > 0) exit(EXIT_SUCCESS);

        // umask(0);
        // setsid();


        // if (chdir("/") < 0) exit(-1);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }    

    if (listen(server_fd, BACKLOG) != 0) {
        syslog(LOG_ERR, "Listen failed: %s", strerror(errno));
        cleanup();
    }

    SLIST_INIT(&head);
    pthread_mutex_init(&file_mutex, NULL);
    setup_timer();
    
    while (is_running) {
        int client_fd = accept(server_fd, (struct sockaddr *)&addr_client, &addr_client_len);
        if (client_fd < 0) {
            syslog(LOG_ERR, "Failed to accept connection.");
            break;
        } else {
            syslog(LOG_ERR, "Accepted connection, creating thread.");
        }

        pthread_t client_id;
        int *client_sockfd_ptr = malloc(sizeof(int));
        *client_sockfd_ptr = client_fd;
        if(pthread_create(&client_id, NULL, connection_handler, client_sockfd_ptr) != 0){
            syslog(LOG_ERR, "Failed to create client thread");
            close(client_fd);
            free(client_sockfd_ptr);
            continue;
        }

        // allocate mem and add thread to linked list
        struct thread_data *tdata = malloc(sizeof(struct thread_data));
        tdata->thread_id = client_id;
        SLIST_INSERT_HEAD(&head, tdata, entries);
    }

}
