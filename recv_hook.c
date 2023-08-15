#define _GNU_SOURCE
#include <dlfcn.h>
#include <time.h>
#include <net/if.h>
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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/ioctl.h> // 添加此头文件
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define FORKSRV_FD 198
#define MAX_LINE_LEN 1024
#define HOOK_STRING "hook"
#define FINIREAD "fini"
#define FILENAME   "finding_dir/default/.cur_input"
int status;
const u_char* packet_data;
timer_t       timer; // register timer
static int flag_recvmsg = 0;
static int flag_recvfrom = 0;
static int flag_read = 0;
static int flag_recv = 0;
static FILE  *fp;
void   send_to_afl();
void   read_from_afl();
int    is_valid_socket(int fd);
void   print_interface_indexes();
int    get_interface_index();
typedef ssize_t (*orig_recv_func_type)(int sockfd, void *buf, size_t len, int flags);
orig_recv_func_type original_recv = NULL;
ssize_t recv(int sockfd, void* buf, size_t len, int flags) {
    if (!original_recv) {
        original_recv = (orig_recv_func_type)dlsym(RTLD_NEXT, "recv");
    }
    printf("recv\n");
    int isNetworkSocket = sd_is_socket(sockfd, AF_UNSPEC, 0, 0);
    if (!isNetworkSocket) {
        printf("not network:%d\n", isNetworkSocket);
        return original_recv(sockfd, buf, len, flags);
    }
    if (flag_recv == 0) {
        char buffer[5];
        if (len >= 4) {
          ssize_t ret = original_recv(sockfd, buffer, 4, MSG_PEEK | MSG_DONTWAIT);
          if (strncmp(buffer, "hook", 4) == 0) {
            flag_recv = 1;
            return 4;
          }
        }
        return original_recv(sockfd, buf, len, flags);
    }
    if (flag_recv) {
        printf("hook\n");
        read_from_afl();
        if (fp == NULL) {
          fp = fopen(FILENAME, "rb");
          fseek(fp, 24, SEEK_SET);
          if (fp == NULL) {
            perror("Could not open pcap file: %s\n");
            return 0;
          }
        }
        int  total_bytes_received = 0;
        long currentPosition = ftell(fp);  // check file lenth
        fseek(fp, 0, SEEK_END);
        long totalLength = ftell(fp);
        long distanceToEnd = totalLength - currentPosition;
        // printf("file_lenth:%ld\n", distanceToEnd);
        fseek(fp, currentPosition, SEEK_SET);
        if (distanceToEnd <= len) {
          total_bytes_received = read(fileno(fp), buf, len);
        } else {
          total_bytes_received = read(fileno(fp), buf, distanceToEnd);
        }
        fclose(fp);
        // printf("current seed done.\n");
        fp = NULL;
        struct sigevent   sev;
        struct itimerspec its;
        signal(SIGALRM, send_to_afl);
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGALRM;
        sev.sigev_value.sival_ptr = &timer;
        timer_create(CLOCK_REALTIME, &sev, &timer);
        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 0;
        its.it_value.tv_sec = 0;
        its.it_value.tv_nsec = 10000;
        timer_settime(timer, 0, &its, NULL);
        read_from_afl();
        timer_delete(timer);
        return total_bytes_received;
    }
}
typedef ssize_t(*recvfrom_t)(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
static recvfrom_t original_recvfrom = NULL;
ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags,
    struct sockaddr* src_addr, socklen_t* addrlen) {
    if (!original_recvfrom) {
        original_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    }
    int check_valid=is_valid_socket(sockfd);
    //printf("%d\n", check_valid);
    int isNetworkSocket = sd_is_socket(sockfd, AF_UNSPEC, 0, 0);
    if (!isNetworkSocket) {
        printf("not network:%d\n", isNetworkSocket);
        return original_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    }
    if (flag_recvfrom==0) {
        char buffer[4];
        if (len >= 4) {
            ssize_t ret = original_recvfrom( sockfd, buffer, 4, MSG_PEEK | MSG_DONTWAIT, src_addr, addrlen);
            if (strncmp(buffer, "hook", 4) == 0) { 
                flag_recvfrom = 1;
                return 4;            
            }
        }
        return original_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
       
    }
    if (flag_recvfrom==1) {
        if (fp == NULL) {
            fp = fopen(FILENAME, "rb");
            fseek(fp, 24, SEEK_SET);
            if (fp == NULL) {
                perror("Could not open pcap file: %s\n");
                return 0;
            }
        }
        int  total_bytes_received = 0;
        long currentPosition = ftell(fp);  // check file lenth
        fseek(fp, 0, SEEK_END);
        long totalLength = ftell(fp);
        long distanceToEnd = totalLength - currentPosition;
        // printf("file_lenth:%ld\n", distanceToEnd);
        fseek(fp, currentPosition, SEEK_SET);
     
        if (distanceToEnd <= len) {
             total_bytes_received= read(fileno(fp), buf, len);    
        }
        else
        {
             total_bytes_received = read(fileno(fp), buf, distanceToEnd); 
        }
        fclose(fp);
        // printf("current seed done.\n");
        fp = NULL;
        struct sigevent   sev;
        struct itimerspec its;
        signal(SIGALRM, send_to_afl);
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGALRM;
        sev.sigev_value.sival_ptr = &timer;
        timer_create(CLOCK_REALTIME, &sev, &timer);
        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 0;
        its.it_value.tv_sec = 0;
        its.it_value.tv_nsec = 10000;
        timer_settime(timer, 0, &its, NULL);
        read_from_afl();
        timer_delete(timer);
        return total_bytes_received;
    }

}
typedef ssize_t (*orig_read_func_type)(int sockfd, void *buf, size_t count);
static orig_read_func_type original_read = NULL;
ssize_t  read(int fd, void *buf, size_t count) {
    //printf("here\n");
    if (!original_read) {
        original_read = (orig_read_func_type)dlsym(RTLD_NEXT, "read");
    }
    if (!original_recv) {
        original_recv = (orig_recv_func_type)dlsym(RTLD_NEXT, "recv");
    }
    int isNetworkSocket = sd_is_socket(fd, AF_UNSPEC, 0, 0);
    if (!isNetworkSocket) {
        //printf("not network:%d\n", isNetworkSocket);
        return original_read(fd, buf, count);
    }
    if (flag_read == 0) {
        char buffer[5];
             ssize_t ret =original_recv(fd, buffer, 4, MSG_PEEK | MSG_DONTWAIT);
             //printf("buffer:%s\n", buffer);
             if (strncmp(buffer, "hook", 4) == 0) {
                flag_read = 1;
                //return 4;
             } else {
                return original_read(fd, buf, count);
                }
    }
    if (flag_read == 1) {
        printf("count:%ld\n", count);
        //
        //printf("hook\n");
        //read_from_afl();
        if (fp == NULL) {
             fp = fopen(FILENAME, "rb");
             fseek(fp, 24, SEEK_SET);
             if (fp == NULL) {
                perror("Could not open pcap file: %s\n");
                return 0;
             }
        }
        int  total_bytes_received = 0;
        long currentPosition = ftell(fp);  // check file lenth
        fseek(fp, 0, SEEK_END);
        long totalLength = ftell(fp);
        long distanceToEnd = totalLength - currentPosition;
        printf("file_lenth:%ld\n", distanceToEnd);
        fseek(fp, currentPosition, SEEK_SET);
        if (distanceToEnd <= count) { 
            total_bytes_received =fread((char*)buf, sizeof(char), distanceToEnd, fp);
            fclose(fp);
            fp = NULL;
            //((char*)buf)[0] = 0x10;
            // fclose(fp);
            //  printf("current seed done.\n");
            // fp = NULL;
            struct sigevent sev;
            struct itimerspec its;
            signal(SIGALRM, send_to_afl);
            sev.sigev_notify = SIGEV_SIGNAL;
            sev.sigev_signo = SIGALRM;
            sev.sigev_value.sival_ptr = &timer;
            timer_create(CLOCK_REALTIME, &sev, &timer);
            its.it_interval.tv_sec = 0;
            its.it_interval.tv_nsec = 0;
            its.it_value.tv_sec = 0;
            its.it_value.tv_nsec = 100000;
            timer_settime(timer, 0, &its, NULL);
            read_from_afl();
            timer_delete(timer);
        } else {
            total_bytes_received = fread((char*)buf, sizeof(char), count, fp);
        }
        printf("buf:%s\n", (char*)buf);
        printf("total_bytes_received:%d\n", total_bytes_received);
        return total_bytes_received;
    }
}
typedef ssize_t(*orig_recvmsg_func_type)(int sockfd, struct msghdr* msg, int flags);
//original recvmsg
static orig_recvmsg_func_type original_recvmsg = NULL;
ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags)
{
    if (!original_recvmsg) {
        original_recvmsg = (orig_recvmsg_func_type)dlsym(RTLD_NEXT, "recvmsg");
    }

    int check_valid = is_valid_socket(sockfd);
    //printf("%d\n", check_valid);
    //printf("recvmsg, msg.msg_iovlen=%ld, msg.msg_iov[0].iov_len=%ld \n", msg->msg_iovlen,
    //    msg->msg_iov[0].iov_len);
    char buffer[5];
    int isNetworkSocket = sd_is_socket(sockfd, AF_UNSPEC, 0 , 0);
    if (!isNetworkSocket) {
        //printf("not network:%d\n",isNetworkSocket);
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
            return 4;
        }
        else {
            return original_recvmsg(sockfd, msg, flags);
        }
    }
    if (flag_recvmsg == 1) 
    {
        //read_from_afl();
        struct sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(10001);  // 将主机字节序转换为网络字节序
        inet_pton(AF_INET, "127.0.0.1", &(target_addr.sin_addr));
        memcpy(msg->msg_name, &target_addr, sizeof(struct sockaddr_in));
        msg->msg_namelen = sizeof(struct sockaddr_in);
        //print_interface_indexes();
        struct ifreq ifr;
        /* ifr.ifr_ifindex = 1;
        if (ioctl(sockfd, SIOCGIFNAME, &ifr) == -1) { perror("ioctl");
        }
        printf("name:%s\n", ifr.ifr_name);*/
        struct in_pktinfo ip_pktinfo_value;
        ip_pktinfo_value.ipi_spec_dst.s_addr =inet_addr("127.0.0.1");  
        ip_pktinfo_value.ipi_ifindex = 1;  
        //printf("index:%d\n", ip_pktinfo_value.ipi_ifindex);
        // 手动填充msg.msg_control
         char   control_buffer[CMSG_SPACE(sizeof(struct in_pktinfo))];
        struct cmsghdr *cmptr = (struct cmsghdr *)control_buffer;
        cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        cmptr->cmsg_level = IPPROTO_IP;
        cmptr->cmsg_type = IP_PKTINFO;
        // 将数据拷贝到msg.msg_control中
        memcpy(CMSG_DATA(cmptr), &ip_pktinfo_value,sizeof(struct in_pktinfo));
        msg->msg_control = control_buffer;
        msg->msg_controllen = cmptr->cmsg_len;
        /* if (msg->msg_flags & MSG_TRUNC) {
            printf("Received message is truncated.\n");
        } else {
            printf("Received message is complete.\n");
        }*/
        /*
        struct sockaddr_storage addr;
        socklen_t               addr_len = sizeof(addr);
        if (getsockname(sockfd, (struct sockaddr *)&addr, &addr_len) < 0) {
            perror("getsockname failed");
            close(sockfd);
            
        }
        if (addr.ss_family == AF_INET) {
            printf("The socket is using IPv4.\n");
        } else if (addr.ss_family == AF_INET6) {
            printf("The socket is using IPv6.\n");
        } else {
            printf("Unknown address family.\n");
        }
        */
        if (fp == NULL) {
            fp = fopen(FILENAME, "rb");
            //fseek(fp, 0, SEEK_SET);
            if (fp == NULL) {
                perror("Could not open file: %s\n");
                return 0;
            }
        }
        int total_bytes_received = 0;
        for (int i = 0; i < msg->msg_iovlen; i++) {
            unsigned char length_bytes[2];
            size_t buffer_size = 0;
            size_t bytes_read = 0;
            long   current_pos;
            long   file_length;
            long   remaining_length;
            char  *buffer;
            int    error_packet = 0;
            fread(length_bytes, sizeof(unsigned char), 2, fp);
            unsigned short length = (length_bytes[0] << 8) | length_bytes[1];
            //printf("length:%d\n",length);
            if (length == 0) {  //认为是错误的包 
                error_packet = 1;
            } else if (length < msg->msg_iov[i].iov_len) {  // 包长度小于缓冲区长度
                buffer_size = length;
                buffer = malloc(buffer_size);
                bytes_read = fread(buffer, sizeof(char), buffer_size, fp);
            }else{  // 种子大于缓冲区长度
                buffer_size = msg->msg_iov[i].iov_len;
                buffer = malloc(buffer_size);
                bytes_read = fread(buffer, sizeof(char), buffer_size, fp);
                current_pos= ftell(fp);
                fseek(fp, 0, SEEK_END);
                file_length = ftell(fp);
                remaining_length = file_length - current_pos;
                //printf("remaining_length:%d\n", remaining_length);
                if (remaining_length <= length + 2) {
                    error_packet = 1;
                    //printf("wrong packet\n");
                } else {
                    fseek(fp, current_pos + length - remaining_length, SEEK_SET);
                }
            }
            /* long current_pos = ftell(fp);
            fseek(fp, 0, SEEK_END);
            long file_length = ftell(fp);
            long remaining_length = file_length - current_pos;
            fseek(fp, current_pos, SEEK_SET);
            printf("remaining_length:%ld\n", remaining_length);*/
            /* if (fseek(fp, length - msg->msg_iov[i].iov_len, SEEK_CUR) !=
                         0 ||
                     bytes_read < buffer_size) {
                fseek(fp, 0, SEEK_END);
            }*/
            //printf("bytes_read:%d\n", bytes_read);
            //printf("buffer_size:%d\n", buffer_size);
            if (!error_packet) {
                total_bytes_received += bytes_read;
                memcpy(msg->msg_iov[i].iov_base, buffer, buffer_size);
                free(buffer);
            }
            if (feof(fp)|| error_packet) { 
                fclose(fp);
                fp = NULL;
                //printf("current seed done.\n");
                struct sigevent   sev;
                struct itimerspec its;
                signal(SIGALRM, send_to_afl);
                sev.sigev_notify = SIGEV_SIGNAL;
                sev.sigev_signo = SIGALRM;
                sev.sigev_value.sival_ptr = &timer;
                timer_create(CLOCK_REALTIME, &sev, &timer);
                its.it_interval.tv_sec = 0;
                its.it_interval.tv_nsec = 0;
                its.it_value.tv_sec = 0;
                its.it_value.tv_nsec = 1;
                timer_settime(timer, 0, &its, NULL);
                read_from_afl();
                timer_delete(timer);
            }
        }
        //printf("total_bytes_received:%d\n", total_bytes_received);
        return total_bytes_received;  
    }
}

void send_to_afl() {
    if (write(FORKSRV_FD + 4, FINIREAD, 4) < 0) {

        perror("wrong in writing to afl-fuzz ");
        //_exit(1);

    }
    //printf("send success\n");
}
void read_from_afl() {
    if (!original_read) {
        original_read = (orig_read_func_type)dlsym(RTLD_NEXT, "read");
    }
    char buf[4];
    int res = 0;
    if ((res = original_read(FORKSRV_FD + 3, buf, 4)) < 0) {
        perror("Don't recv hello?(OOM?)read_from_afl:");
        //_exit(1);
    }
    //printf("read success\n");
}  
int close(int fd) {
    if (fd == FORKSRV_FD + 3 || fd == FORKSRV_FD + 4) {
        return 0;
    }
    int (*original_close)(int);
    original_close = dlsym(RTLD_NEXT, "close");
    return original_close(fd);
}
int is_valid_socket(int fd) {
    // 使用 F_GETFL 标志获取文件描述符状态
    int flags = fcntl(fd, F_GETFL);

    // 如果 fcntl 成功执行，说明文件描述符是有效的
    return (flags != -1);
}
void print_interface_indexes() {
    struct if_nameindex *if_nidxs, *intf;

    if_nidxs = if_nameindex();
    if (if_nidxs == NULL) {
        perror("if_nameindex");
        return;
    }

    // 遍历网络接口列表并打印索引和名称
    for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL;
         intf++) {
        printf("Interface name: %s, Index: %u\n", intf->if_name,
               intf->if_index);
    }

    // 释放资源
    if_freenameindex(if_nidxs);
}
int get_interface_index(int sockfd) {
    // 获取套接字绑定的本地地址
    struct sockaddr_in local_addr;
    socklen_t          addr_len = sizeof(local_addr);
    if (getsockname(sockfd, (struct sockaddr *)&local_addr, &addr_len) == -1) {
        perror("getsockname");
        return -1;
    }

    // 将本地地址的 IP 转换为字符串
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(local_addr.sin_addr), ip_str, INET_ADDRSTRLEN);

    // 使用 if_nametoindex 函数获取与 IP 相关联的网络接口索引
    unsigned int interface_index = if_nametoindex("eth0");
    if (interface_index == 0) {
        perror("if_nametoindex");
        return -1;
    }

    // 返回获取到的网络接口索引
    return interface_index;
}
