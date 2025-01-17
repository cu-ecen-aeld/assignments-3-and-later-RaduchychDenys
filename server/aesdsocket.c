#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include <fcntl.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>


    // open stream socket on port 9000 | Done
    // return 1 if something is wrong | Done
    // write messages to the system log "Accepted connection from X.X.X.X" | Done
    // read data and append it to the /var/tmp/aesdsocketdata. Create file if it does not exist | Done
    // use new line as delimiter between recieved packets | PACKED RECIEVED WHEN THE NEW LINE SYMBOLL IS FOUND | Done
    // return the full content of the  aesdsocketdata file to the client | Done
    // log message to the system log "Closed connection from X.X.X.X" | Done
    // accept connection until SIGINT and SIGTERM | Done
    // done all sending operations and REMOVE file | Done 
    // log message "Caugth signal, exiting" in the system logs | Done
    // Modify your program to support a -d argument which runs the aesdsocket application as a daemon. | Done
    // When in daemon mode the program should fork after ensuring it can bind to port 9000.  | Done

#define GENERAL_ERROR 1
#define SIGNAL_EXIT_ERROR  2

const char* logFilePath = "/var/tmp/aesdsocketdata";

typedef enum _clientStatus
{
    SUCCESS_STATUS = 0,
    SOCKET_ERROR_STATUS = 1,
    WRITE_ERROR_STATUS = 2,
    READ_FILE_ERROR_STATUS = 3,
    SEND_ERROR_STATUS = 4,
    COUNT_STATUS
}clientStatus;

//Global program state

sigset_t g_SignalsMask;

int g_SignalNum = 0;
int g_BaseSocket = -1;
char* g_Buffer = NULL;

pid_t g_ParentId = 0;
int g_ParentExitCode = 0;

void send_exit_signal_to_parent(int status)
{
    if(g_ParentId && getpid() != g_ParentId)
    {
        union sigval sigdata;
        sigdata.sival_int = status;
        if (sigqueue(g_ParentId, SIGQUIT, sigdata) != 0 )
        {
            syslog(LOG_ERR, "Can not send exit signal to the parent with exit status. Error:%d %s", errno, strerror(errno));
            if (kill(g_ParentId, SIGKILL) != 0 )
            {
                syslog(LOG_ERR, "Can not send kill signal to the parent process. Error:%d %s", errno, strerror(errno));
            }
        }
    }
}

void handle_signal(const int signalNum)
{
    g_SignalNum = signalNum;
}

void handle_quit_signal_from_child(int signum, siginfo_t* info, void* data)
{
    //Exit from the process with the given return code that located in the data variable
    if(info != NULL)
    {
        g_ParentExitCode = info->si_int;
        return;
    }

    g_ParentExitCode = SIGNAL_EXIT_ERROR;
}

void check_signal()
{
    if(g_SignalNum != 0)
    {
        printf("Got a signal %d %s. Exit from the app\n", g_SignalNum, strsignal(g_SignalNum));
        remove(logFilePath);
        syslog(LOG_INFO, "Caugth signal, exiting");
        exit(0);
    }
}

ssize_t packet_length(const char const * buff, const ssize_t buffsize, bool* isLast)
{
    if( buffsize == 0 )
    {
        return 0;
    }

    for(ssize_t i = 0; i < buffsize; i++)
    {
        if( buff[i] == '\n' )
        {
            *isLast = true;
            return i + 1;
        }
    }

    return buffsize;
}

clientStatus handle_client(const int clientSocket, char* buff, ssize_t buffsize, const int writeFile)
{
        ssize_t len = -1;
        int error = 0;
        bool isLast = false;

        while(1)
        {
            len = recv(clientSocket, buff, buffsize, 0);

            syslog(LOG_INFO, "Readed packet with length:%ld", len);

            if( len < 0 )
            {
                error = errno;
                syslog(LOG_ERR, "Can not read from a client socket. Error:%d %s\n", error, strerror(error));
                return SOCKET_ERROR_STATUS;
            }

            const ssize_t packetLen = packet_length(buff, len, &isLast);

            syslog(LOG_INFO, "Estimated packet length:%ld", packetLen);

            const ssize_t writeResult = write(writeFile, buff, packetLen);

            syslog(LOG_INFO, "Length of the data was written to the file:%ld", writeResult);

            if( writeResult < 0 || writeResult != packetLen)
            {
                error = errno;
                syslog(LOG_ERR, "Can not write to the file. Error:%d %s\n", error, strerror(error));
                return WRITE_ERROR_STATUS;
            }


            if( isLast )
            {

                error = fdatasync(writeFile);

                if(error != 0 )
                {
                    error = errno;
                    syslog(LOG_ERR, "Can not flush and sync file for writing. Error:%d %s\n", error, strerror(error));
                    error = 0;
                }

                const int fileHandle = open(logFilePath, O_RDONLY);
                ssize_t readResult = -1;

                while( (readResult = read(fileHandle, buff, buffsize)) != 0 )
                {
                    if ( readResult <= 0 )
                    {
                        error = errno;
                        syslog(LOG_ERR, "Can not read from the file. Error:%d %s\n", error, strerror(error));
                        return READ_FILE_ERROR_STATUS;
                    }

                    const int sendResult = send(clientSocket, buff, readResult, 0);

                    if( sendResult <= 0 )
                    {
                        error = errno;
                        syslog(LOG_ERR, "Can not send data to a client. Error:%d %s\n", error, strerror(error));
                        return SEND_ERROR_STATUS;
                    }
                }

                shutdown(clientSocket, SHUT_RDWR);
                close(fileHandle);
                return  SUCCESS_STATUS;
            }
        }

        return SUCCESS_STATUS;
}

void run_server(int baseSocket)
{
    int error = 0;

    const int fileHandle = open(logFilePath, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );

    if( fileHandle <= 0)
    {
        error = errno;
        syslog(LOG_ERR, "Can not open file for writing. Error:%d %s\n", error, strerror(error));
        send_exit_signal_to_parent(GENERAL_ERROR);
        exit(GENERAL_ERROR);
    }

    const size_t buffsize = 1024 * 64;
    char* buff = (char*)malloc(buffsize);

    if( buff == NULL)
    {
        error = errno;
        syslog(LOG_ERR, "Can not allocate buffer. Error:%d %s\n", error, strerror(error));
        send_exit_signal_to_parent(GENERAL_ERROR);
        exit(GENERAL_ERROR);
    }

    g_Buffer = buff;

    send_exit_signal_to_parent(EXIT_SUCCESS);

    while(1)
    {

        check_signal();

        if ( listen(baseSocket, SOMAXCONN - 1) != 0)
        {
            error = errno;
            syslog(LOG_ERR, "Can not listen base socket. Error: %d %s\n", error, strerror(error));
            exit(GENERAL_ERROR);
        }


        struct sockaddr clientAddr;
        socklen_t clientAddrLen = sizeof(struct sockaddr);

        const int clientSocket = accept(baseSocket, &clientAddr, &clientAddrLen);

        if( clientSocket == -1)
        {
            check_signal();

            error = errno;
            syslog(LOG_ERR, "Can not accept client. Error:%d %s\n", error, strerror(error));
            //return GENERAL_ERROR;
            continue;
        }

        if( sigprocmask(SIG_BLOCK, &g_SignalsMask, NULL)) // block recieving of these signals
        {
            error = errno;
            syslog(LOG_ERR, "Can not block signals. Error:%d %s\n", error, strerror(error));
            exit(GENERAL_ERROR);
        }

        struct sockaddr_in* clientAddrIn = (struct sockaddr_in*)(&clientAddr);
        char clientIpAddr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &(clientAddrIn->sin_addr), clientIpAddr, INET_ADDRSTRLEN);

        syslog(LOG_INFO, "Accepted connection from %s", clientIpAddr);

        clientStatus result = handle_client(clientSocket, buff, buffsize, fileHandle);

        switch(result)
        {
            case WRITE_ERROR_STATUS:
            case READ_FILE_ERROR_STATUS:
                error = errno;
                syslog(LOG_ERR, "Can not perfrom operation with the log file:%s. Error:%d %s", logFilePath, error, strerror(error));
                exit(GENERAL_ERROR);
        }


        syslog(LOG_INFO, "Closed connection from %s", clientIpAddr);

        if( sigprocmask(SIG_UNBLOCK, &g_SignalsMask, NULL) != 0 ) //unlock recieving of these signals
        {
            error = errno;
            syslog(LOG_ERR, "Can not unblock signals. Error:%d %s\n", error, strerror(error));
            exit(GENERAL_ERROR);
        }
    }

/*
    shutdown(baseSocket, SHUT_RDWR);
    close(baseSocket);
*/
}

int init_base_socket()
{
    int error = 0;

    struct addrinfo hints;

    struct addrinfo* res = NULL;

    const int baseSocket = socket(AF_INET, SOCK_STREAM, 0);

    if( baseSocket <= 0 )
    {
        error = errno;
        syslog(LOG_ERR, "Can not open socket. Error:%d %s\n", error, strerror(error));
        exit(GENERAL_ERROR);
    }


    //Set socket options
    const int enable = 1;
    if ( setsockopt(baseSocket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0 ||
         setsockopt(baseSocket, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0 )
    {
        error = errno;
        syslog(LOG_ERR, "Can not set socket options. Error:%d %s\n", error, strerror(error));
        exit(GENERAL_ERROR);
    }


    memset(&hints, 0x00, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if( (error = getaddrinfo(NULL, "9000" , &hints, &res)) != 0 )
    {
        syslog(LOG_ERR, "Can not get address. Error:%d %s\n", error, gai_strerror(error));
        exit(GENERAL_ERROR);
    }

    if ( bind(baseSocket, res->ai_addr, sizeof(struct sockaddr)) != 0 )
    {
        error = errno;
        syslog(LOG_ERR, "Can not bind socket. Error:%d %s\n", error, strerror(error));
        freeaddrinfo(res);
        exit(GENERAL_ERROR);
    }

    freeaddrinfo(res);

    g_BaseSocket = baseSocket;

    return baseSocket;
}

void init_signals_logic()
{
    int error = 0;

    sigemptyset(&g_SignalsMask);
    sigaddset(&g_SignalsMask, SIGINT);
    sigaddset(&g_SignalsMask, SIGTERM);

    struct sigaction actionINT;
    struct sigaction actionTERM;

    sigemptyset(&actionINT.sa_mask);
    actionINT.sa_handler = handle_signal;
    actionINT.sa_flags = 0;

    sigemptyset(&actionTERM.sa_mask);
    actionTERM.sa_handler = handle_signal;
    actionTERM.sa_flags = 0;

    if( sigaction(SIGINT, &actionINT, NULL) != 0 ||
        sigaction(SIGTERM, &actionTERM, NULL) != 0 )
    {
        error = errno;
        syslog(LOG_ERR, "Can not registry signal handlers. Error:%d %s\n", error, strerror(error));
        send_exit_signal_to_parent(GENERAL_ERROR);
        exit(GENERAL_ERROR);
    }
}

void exit_func()
{
    if(g_BaseSocket != -1)
    {
        close(g_BaseSocket);
    }

    if(g_Buffer != NULL)
    {
        free(g_Buffer);
    }
}

void init_demon(const int baseSocket)
{
    int error = 0;
    int pid = fork();

    if( pid < 0 )
    {
        error = errno;
        syslog(LOG_ERR, "Can not for fork. Error%d %s\n", error, strerror(error));
        exit(GENERAL_ERROR);
    }

    if( pid > 0 )
    {
        return;
    }

    if( setsid() < 0 )
    {
        error = errno;
        syslog(LOG_ERR, "Can not set session id. Error:%d %s\n", error, strerror(error));
        send_exit_signal_to_parent(GENERAL_ERROR);
        exit(GENERAL_ERROR);
    }

    if( chdir("/") != 0 )
    {
        error = errno;
        syslog(LOG_ERR, "Can not change dir to the root directory. Error:%d %s\n", error, strerror(error));
        send_exit_signal_to_parent(GENERAL_ERROR);
        exit(GENERAL_ERROR);
    }

    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        if(x != baseSocket)
        {
            close (x);
        }
    }

    int null = open("/dev/null", O_WRONLY);

    if( null < 0 )
    {
        error = errno;
        syslog(LOG_ERR, "Can not open null device. Errro:%d %s\n", error, strerror(error));
        send_exit_signal_to_parent(GENERAL_ERROR);
        exit(GENERAL_ERROR);
    }

    if( dup2(null, 0 ) < 0 ||
        dup2(null, 1) < 0 ||
        dup2(null, 2) < 0 )
    {
        error = errno;
        syslog(LOG_ERR, "Can not redirect output to the null device. Error:%d %s", error, strerror(error));
        send_exit_signal_to_parent(GENERAL_ERROR);
        exit(GENERAL_ERROR);
    }
}

int main(int argc, char** argv)
{
    int opt = getopt(argc, argv, "d");

    if( opt == 'd')
    {
        openlog("aesdsocket", LOG_PID, LOG_DAEMON);

        struct sigaction parent_quit_action;
        parent_quit_action.sa_sigaction = handle_quit_signal_from_child;

        if (sigaction(SIGQUIT, &parent_quit_action, NULL) != 0)
        {
            syslog(LOG_ERR, "Can not registry quit handler. Error:%d %s", errno, strerror(errno));
            exit(GENERAL_ERROR);
        }

        g_ParentId = getpid();

    }
    else
    {
        openlog("aesdsocket", LOG_PERROR, LOG_USER);
    }

    const int baseSocket = init_base_socket();

    if( opt == 'd') //demon mode
    {
        init_demon(baseSocket);
        if(g_ParentId == getpid())
        {
            //Parent thread must wait signal with return code from the child
            syslog(LOG_INFO, "Start wait QUIT signal from the child process");
            pause();
            syslog(LOG_INFO, "Exit from the parent process with status code:%d", g_ParentExitCode);
            exit(g_ParentExitCode);
        }
    }

    if( atexit(exit_func) != 0)
    {
        int error = errno;
        syslog(LOG_ERR, "Can not registry exit clean up function. Error:%d %s", error, strerror(error));
        exit(GENERAL_ERROR);
    }

    init_signals_logic();

    run_server(baseSocket);

    return EXIT_SUCCESS;
}
