#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <systemd/sd-daemon.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
void send_to_afl();
void read_from_afl();
#define FORKSRV_FD 198
#define MAX_LINE_LEN 1024
#define HOOK_STRING "hook"
#define FINIREAD "fini"
#define FILENAME   "finding_dir/default/.cur_input"
int status;
const u_char* packet_data;
static int flag_recvmsg = 0;
static int flag_recvfrom = 0;
static int flag_recv = 0;
typedef ssize_t(*orig_recv_func_type)(int sockfd, void* buf, size_t len, int flags);
orig_recv_func_type original_recv = NULL;
static FILE* fp;
typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} PcapPacketHeader;
static FILE* fp;
ssize_t recv(int sockfd, void* buf, size_t len, int flags) {
    if (!original_recv) {
        original_recv = (orig_recv_func_type)dlsym(RTLD_NEXT, "recv");
    }
    char buffer[len];
    printf("recv\n");
    ssize_t ret = (*original_recv)(sockfd, buffer, len, MSG_PEEK);
    if (ret >= 4 && !flag_recv) {
        if (ret >= 4 && strncmp(buffer, "hook", 4) == 0) {
            flag_recv = 1;
        }
    }
    if (flag_recv) {
        printf("here\n");
        read_from_afl();
        if (fp == NULL) {
            fp = fopen(FILENAME, "rb");
            fseek(fp, 24, SEEK_SET);
            send_to_afl();
            if (fp == NULL) {
                perror("Could not open pcap file: %s\n");
                return 1;
            }
        }
        PcapPacketHeader header;
        fread(&header, sizeof(header), 1, fp);
        uint32_t packetSize = header.incl_len;
        fread(buf, packetSize, 1, fp);
        if (feof(fp)) {
            fclose(fp);
            fp = NULL;
        }
        return strlen(buf);


    }
    return original_recv(sockfd, buf, len, flags);
}

//check if magic characters has been received
/*typedef ssize_t(*recvfrom_t)(int sockfd, void* buf, size_t len, int flags,
    struct sockaddr* src_addr, socklen_t* addrlen);
//original recvfrom
static recvfrom_t original_recvfrom = NULL;
ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags,
    struct sockaddr* src_addr, socklen_t* addrlen) {
    //check if recvfrom() exists
    if (original_recvfrom == NULL) {
        //get original recvfrom()
        original_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    }
    //define my own magic characters
    char* buffer[len];
    printf("here");
    ssize_t ret = original_recvfrom(sockfd, buffer, len, MSG_PEEK,
        src_addr, addrlen);

    if (ret >= 4 && !flag_recv) {
        if (ret >= 4 && strncmp(buffer, "hook", 4) == 0) {
            flag_recv = 1;
        }
    }
    if (flag_recv) {
        printf("here\n");
        read_from_afl();
        if (fp == NULL) {
            fp = fopen(FILENAME, "rb");
            fseek(fp, 24, SEEK_SET);
            send_to_afl();
            if (fp == NULL) {
                perror("Could not open pcap file: %s\n");
                return 1;
            }
        }


    }
    return original_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}*/
//TODO: sd判断socket
//TODO: 注意msg长度，在种子都完成之后向AFL要下一个种子
//TODO: 1ms之后向afl发送完成消息
typedef ssize_t(*orig_recvmsg_func_type)(int sockfd, struct msghdr* msg, int flags);
//original recvmsg
static orig_recvmsg_func_type original_recvmsg = NULL;
//check if recvmsg() exists
ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags)
{
    if (!original_recvmsg) {
        original_recvmsg = (orig_recvmsg_func_type)dlsym(RTLD_NEXT, "recvmsg");
    }
    printf("recvmsg, msg.msg_iovlen=%ld, msg.msg_iov[0].iov_len=%ld \n", msg->msg_iovlen,
        msg->msg_iov[0].iov_len);
    char buffer[5];
    int isNetworkSocket = sd_is_socket(sockfd, AF_UNSPEC, 0 , 0);
    if (!isNetworkSocket) {
        printf("not network:%d\n",isNetworkSocket);
        return original_recvmsg(sockfd, msg, flags);
    }
    if (flag_recvmsg == 0) {
        struct msghdr my_msg = { 0 };
        struct iovec iov[1];
        iov[0].iov_base = buffer;
        iov[0].iov_len = 4;
        my_msg.msg_iov = iov;
        my_msg.msg_iovlen = 1;
        ssize_t bytesReceived =original_recvmsg(sockfd, &my_msg, MSG_DONTWAIT | MSG_PEEK);
        buffer[4] = '\0';
        //printf("original_recvmsg called bytesReceived=%ld %#08x, %d\n",
         //   bytesReceived, *(int*)(buffer), buffer[1]);
        //printf("%s\n", buffer);
        if (strncmp(buffer, "hook", 4) == 0) {
            printf("flag_recvmsg==1\n");
            flag_recvmsg = 1;

        }
        else {
            return original_recvmsg(sockfd, msg, flags);
        }
    }
    if (flag_recvmsg == 1) {

        if (feof(fp)) {   //check current seed whether have been done
            fclose(fp);
            printf("current seed done.\n");
            fp = NULL;
            send_to_afl()
        }

        read_from_afl();
        int total_bytes_received = 0;
        for (int i=0; i < msg->msg_iovlen; i++) {
            total_bytes_received += msg->msg_iov[i].iov_len;
            if (fp == NULL) {
                fp = fopen(FILENAME, "rb");
                fseek(fp, 24, SEEK_SET);
                if (fp == NULL) {
                    perror("Could not open pcap file: %s\n");
                    return 1;
                }
            }
            long currentPosition = ftell(fp);
            fseek(fp, 0, SEEK_END);
            long totalLength = ftell(fp); 
            long distanceToEnd = totalLength - currentPosition;
            fseek(fp, currentPosition, SEEK_SET);
            if (distanceToEnd < msg->msg_iov[i].iov_len) {
                fread(msg->msg_iov[i].iov_base,distanceToEnd, 1, fp);
            }
            else {
                fread(msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, 1, fp);
            }
            if (feof(fp)) {
                return total_bytes_received;
                /*fclose(fp);
                printf("current seed done.\n");
                fp = NULL;
                usleep(100000);
                send_to_afl();*/
                
            }
        }
      
    }
}
void send_to_afl() {
    if (write(FORKSRV_FD + 4, FINIREAD, 4) < 0) {

        perror("wrong in writing to afl-fuzz ");
        //_exit(1);

    }
}
void read_from_afl() {
    char buf[4];
    int res = 0;
    if ((res = read(FORKSRV_FD + 3, buf, 4)) < 0) {
        perror("Don't recv hello?(OOM?)read_from_afl:");
        //_exit(1);
    }
}  int close(int fd) {
    if (fd == FORKSRV_FD + 3 || fd == FORKSRV_FD + 4) {
        return 0;
    }
    int (*original_close)(int);
    original_close = dlsym(RTLD_NEXT, "close");
    return original_close(fd);
}
