#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <malloc.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/ptrace.h>

typedef enum
{
    SS_FREE = 0,
    SS_UNCONNECTED,
    SS_CONNECTING,
    SS_CONNECTED,
    SS_DISCONNECTING
} socket_state;

typedef enum
{
    SOCK_STREAM,
    SOCK_DGRAM,
    SOCK_RAW,
    SOCK_RDM,
    SOCK_SEQPACKET,
    SOCK_DCCP,
    SOCK_PACKET
} sock_type;

#define SOCKWQ_ASYNC_NOSPACE 0
#define SOCKWQ_ASYNC_WAITDATA 1
#define SOCK_NOSPACE 2
#define SOCK_PASSCRED 3
#define SOCK_PASSSEC 4

struct socket_info
{
    int fd;
    socket_state state;
    sock_type type;
    unsigned long flags;
};

struct socket_count_message
{
    int count;
};

struct sockets_info_message
{
    int count;
    struct socket_info *sockets;
};

struct context_len_message
{
    int len;
};

struct context_info_message
{
    int maxlen;
    char *str;
};

struct ioctl_message
{
    pid_t pid;
    bool err;
    union
    {
        struct socket_count_message socket_count_m;
        struct sockets_info_message sockets_info_m;
        struct context_len_message context_len_m;
        struct context_info_message context_info_m;
    } data;
};

#define WR_SOCKET_COUNT _IOW('a', 2, struct ioctl_message *)
#define WR_SOCKET_INFO _IOW('a', 3, struct ioctl_message *)
#define WR_CONTEXT_LEN _IOW('a', 4, struct ioctl_message *)
#define WR_CONTEXT_INFO _IOW('a', 5, struct ioctl_message *)

char *socket_state_to_str(socket_state state)
{
    switch (state)
    {
    case SS_FREE:
        return "SS_FREE";
    case SS_UNCONNECTED:
        return "SS_UNCONNECTED";
    case SS_CONNECTING:
        return "SS_CONNECTING";
    case SS_CONNECTED:
        return "SS_CONNECTED";
    case SS_DISCONNECTING:
        return "SS_DISCONNECTING";
    }
    return 0;
}

char *socket_type_to_str(short type)
{
    switch (type)
    {
    case SOCK_STREAM:
        return "SOCK_STREAM";
    case SOCK_DGRAM:
        return "SOCK_DGRAM";
    case SOCK_RAW:
        return "SOCK_RAW";
    case SOCK_RDM:
        return "SOCK_RDM";
    case SOCK_SEQPACKET:
        return "SOCK_SEQPACKET";
    case SOCK_DCCP:
        return "SOCK_DCCP";
    case SOCK_PACKET:
        return "SOCK_PACKET";
    }
    return 0;
}

void print_socket_flags(unsigned long flags)
{
    if (flags & (1 << SOCKWQ_ASYNC_NOSPACE))
    {
        printf("SOCKWQ_ASYNC_NOSPACE \n");
    }
    if (flags & (1 << SOCKWQ_ASYNC_WAITDATA))
    {
        printf("SOCKWQ_ASYNC_WAITDATA \n");
    }
    if (flags & (1 << SOCK_NOSPACE))
    {
        printf("SOCK_NOSPACE \n");
    }
    if (flags & (1 << SOCK_PASSCRED))
    {
        printf("SOCK_PASSCRED \n");
    }
    if (flags & (1 << SOCK_PASSSEC))
    {
        printf("SOCK_PASSSEC \n");
    }
}

void print_socket_info(struct socket_info *info)
{
    printf("Socket: \n");
    printf("File descriptor: %d \n", info->fd);
    printf("State: %s \n", socket_state_to_str(info->state));
    printf("Type: %s \n", socket_type_to_str(info->type));
    printf("Flags: \n");
    print_socket_flags(info->flags);
    printf("\n");
}

int count_sockets_by_pid(int fd, int pid)
{
    struct ioctl_message message = {0};
    message.pid = pid;
    ioctl(fd, WR_SOCKET_COUNT, (struct ioctl_message *)&message);
    if (message.err)
    {
        return 0;
    }
    return message.data.socket_count_m.count;
}

int get_socket_info(int fd, int pid, struct socket_info *sockets, int count)
{
    struct ioctl_message message = {0};
    message.pid = pid;
    message.data.sockets_info_m.count = count;
    message.data.sockets_info_m.sockets = sockets;
    ioctl(fd, WR_SOCKET_INFO, (struct ioctl_message *)&message);
    return message.err;
}

int get_context_len(int fd, int pid, int *len)
{
    struct ioctl_message message = {0};
    message.pid = pid;
    ioctl(fd, WR_CONTEXT_LEN, (struct ioctl_message *)&message);
    *len = message.data.context_len_m.len;
    return message.err;
}

int get_context_info(int fd, int pid, char **str)
{
    struct ioctl_message message = {0};
    message.pid = pid;
    int maxlen;
    if (get_context_len(fd, pid, &maxlen))
    {
        return 1;
    }
    message.data.context_info_m.maxlen = maxlen;
    message.data.context_info_m.str = malloc(sizeof(char) * (maxlen + 1));
    if (message.data.context_info_m.str == 0) {
        printf("Unable to allocate memory \n");
        return 1;
    }
    ioctl(fd, WR_CONTEXT_INFO, (struct ioctl_message *)&message);
    *str = message.data.context_info_m.str;
    return message.err;
    return -1;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Not enough arguments. Enter PID \n");
        return -1;
    }
    if (argc > 2)
    {
        printf("Too many arguments. Enter PID \n ");
        return -1;
    }

    int fd;
    fd = open("/dev/etx_device", O_RDWR);
    if (fd < 0)
    {
        printf("Cannot open device file \n");
        return -1;
    }

    int pid = atoi(argv[1]);
    if (!pid)
    {
        printf("Wrong PID");
        return -1;
    }

    { // Print sockets
        int count = count_sockets_by_pid(fd, pid);
        struct socket_info *sockets = malloc(sizeof(struct socket_info) * count);
        int err = get_socket_info(fd, pid, sockets, count);
        if (err)
        {
            printf("Error while reading sockets info \n");
            return -1;
        }
        else
        {
            for (int i = 0; i < count; i++)
            {
                print_socket_info(&(sockets[i]));
            }
        }
        free(sockets);
    }

    { // Print context
        char *context_str = 0;
        int err = get_context_info(fd, pid, &context_str);
        if (err)
        {
            printf("Context Err \n");
            return -1;
        }
        else
        {
            printf("Task security context: \n%s \n", context_str);
        }
        free(context_str);
    }

    close(fd);
}
