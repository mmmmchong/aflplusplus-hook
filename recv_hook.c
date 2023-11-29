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
#include <sys/ioctl.h>  // 添加此头文件
#include <sys/stat.h>   // for stat
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/epoll.h>


typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

// 改为0禁掉打印,1启用打印
#define DEBUG 0
#define FORKSRV_FD 198
#define MAX_LINE_LEN 1024

#define MAX_PACKET_NUM 1024
#define HOOK_STRING "hook"
#define FINIREAD "1111"

char *        FILENAME = "mqtt_finding_dir/default/.cur_input";
char *        NUM_FILENAME = "mqtt_finding_dir/default/.num_cur_input";

timer_t       timerid;
static int    flag_recvmsg = 0;
static int    flag_recvfrom = 0;
static int    flag_read = 0;
static int    flag_recv = 0;
static int    first_read = 1;

int           hook_fd;                           // 需要hook的fd
int64_t       last_num_cur_input = 0;

static unsigned int       packet_num;            //packet num
static unsigned int *     packet_length;         // packet length
static unsigned int       seed_length = 0;       //seed length
static unsigned int       orig_seed_length = 0;       // seed length

static int      need_seed = 1;
static FILE     *fp;

unsigned int *read_numfile(void);
void setup_timer();
void send_to_afl();
void read_from_afl();
int  is_valid_socket(int fd);
void          set_manual_cliaddr(struct sockaddr_in *cliaddr);

void          printHex(const char *buf, int len) {
  for (int i = 0; i < len; i++) {
    printf("%02X ", (unsigned char)buf[i]);
  }
  printf("\n");
}

// 1表示需要，0表示不需要
int need_reopen_input() {
  // 打开文件
  FILE *file = fopen(NUM_FILENAME, "rb");
  if (file == NULL) {
    perror("Failed to open file");
    return 0;
  }

  // 读取8字节整数
  int64_t value;
  size_t  bytesRead = fread(&value, sizeof(value), 1, file);
  if (bytesRead != 1) {
    if (feof(file)) {
      //printf("Reached end of file\n");
    } else {
      perror("Failed to read from file");
    }
    fclose(file);
    file = NULL;
    return 0;
  }

    // 关闭文件
  fclose(file);
  file = NULL;

  // 打印读取的整数
  //printf("Read num value: %lld\n", value);
  if (last_num_cur_input != value) { 
      last_num_cur_input = value;
      return 1;
  } else {
    return 0;
  }

}


/*typedef int (*orig_epoll_ctl_type)(int, int, int, struct epoll_event *);
// hook 函数
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
  orig_epoll_ctl_type orig_epoll_ctl;
  orig_epoll_ctl = (orig_epoll_ctl_type)dlsym(RTLD_NEXT, "epoll_ctl");

  // 如果操作是 EPOLL_CTL_DEL，则不调用原始函数
  if (op == EPOLL_CTL_DEL) {
    printf("epoll_ctl hook: Preventing EPOLL_CTL_DEL for fd %d\n", fd);
    return 0;  // 假装成功执行
  }

  // 对于其他操作，调用原始的 epoll_ctl 函数
  return orig_epoll_ctl(epfd, op, fd, event);
}*/


typedef ssize_t (*orig_recv_func_type)(int sockfd, void *buf, size_t len, int flags);
orig_recv_func_type original_recv = NULL;
ssize_t   recv(int sockfd, void *buf, size_t len, int flags) {
  if (!original_recv) {
    original_recv = (orig_recv_func_type)dlsym(RTLD_NEXT, "recv");
  }
  //printf("recv\n");

  int isNetworkSocket = sd_is_socket(sockfd, AF_UNSPEC, 0, 0);
  if (!isNetworkSocket) {
    printf("not network:%d\n", isNetworkSocket);
    return original_recv(sockfd, buf, len, flags);
  }
  
  if (flag_recv == 0) {
    char    buffer[5];
    ssize_t ret = original_recv(sockfd, buffer, 4, MSG_PEEK | MSG_DONTWAIT); 

    if (strncmp(buffer, "hook", 4) == 0) {  /// 收到hook从本地读取
      flag_recv = 1;
      // hook_fd = fd;
    } else {
      return original_recv(sockfd, buf, len, flags);  // 来自网络但不是hook
    }
  }

 if (flag_recv == 1) {  //&& fd == hook_fd

    int needread = 0;

    if (first_read) {
      read_from_afl();  // 第一次需要从afl收到hook
      first_read = 0;
      // need_reopen_input();    //第一次直接读，更新一下 last_num_cur_input
      needread = 1;
    } else if (need_seed) {  // 如果不是第一次但是需要种子则打开
      send_to_afl();
      read_from_afl();
      // need_reopen_input();    //更新一下 last_num_cur_input
      needread = 1;
    }

    if (seed_length > 0) {
      int   count = 0;
      FILE *num_file = fopen(NUM_FILENAME, "rb");
      if (!num_file) { perror("Open num_file for read failed"); }
      if (fread(&count, sizeof(count), 1, num_file) != 1) {
        perror("wrong in read");
        // exit(2);
      }
      fclose(num_file);
      num_file = NULL;
      if (count != orig_seed_length) {
        if (fp != NULL) {
          fclose(fp);
          fp = NULL;
        }
        needread = 1;
      }
    }

    if (needread) {
      //printf("hook read numfile\n");

      fp = fopen(FILENAME, "rb");

      FILE *num_file = fopen(NUM_FILENAME, "r");
      if (!num_file) { perror("Open num_file for read failed"); }

      if (fread(&seed_length, sizeof(seed_length), 1, num_file) != 1) {
        perror("wrong in read");
      }
      fclose(num_file);
      num_file = NULL;
     // printf("seed_length:%d\n", seed_length);

      orig_seed_length = seed_length;

      needread = 0;
    }

    int    total_bytes_received = 0;
    size_t buffer_size = 0;
    size_t bytes_read = 0;
    long   file_length;
    long   remaining_length;
    int    error_packet = 0;

    int real_read = 0;
    //printf("len:%ld\n", len);

    static u8 *numfile_buffer = NULL;

    static u8 counted_length = 0;

    if (seed_length == 0) {
      error_packet = 1;

    } else if (seed_length <= len) {  // 此时我们需要新的seed

      real_read = fread(buf, sizeof(char), seed_length, fp);

      if (DEBUG) {
        //printf("buf:\n");
        //printf("real_read=%d\n", real_read);
        printHex(((char *)buf), real_read);
      }

      total_bytes_received += real_read;

      seed_length = 0;
    } else {  // len<seed_length

      real_read = fread(buf, sizeof(char), len, fp);

      if (DEBUG) {
        //printf("buf:\n");
        //printf("real_read=%d\n", real_read);
        printHex(((char *)buf), real_read);
      }

      total_bytes_received += real_read;

      seed_length -= (int)len;
    }

    if (len > 8096) { 
    error_packet = 1; 
    //exit(2);
    }

    //printf("seed_length:%d\n", seed_length);

    need_seed = 0;
    if (feof(fp) || error_packet > 0 || seed_length == 0) {
      need_seed = 1;
    fclose(fp);
    fp = NULL;
      //printf("need new seed\n");
    }

    return total_bytes_received;
  }
}

typedef ssize_t (*recvfrom_t)(int sockfd, void *buf, size_t len, int flags,
                              struct sockaddr *src_addr, socklen_t *addrlen);
static recvfrom_t original_recvfrom = NULL;
ssize_t           recvfrom(int sockfd, void *buf, size_t len, int flags,
                           struct sockaddr *src_addr, socklen_t *addrlen) {
  if (!original_recvfrom) { original_recvfrom = dlsym(RTLD_NEXT, "recvfrom"); }

  int check_valid = is_valid_socket(sockfd);
  // printf("%d\n", check_valid);
  int isNetworkSocket = sd_is_socket(sockfd, AF_UNSPEC, 0, 0);

  if (!isNetworkSocket) {
    printf("not network:%d\n", isNetworkSocket);
    return original_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
  }

  if (flag_recvfrom == 0) {
    char buffer[4];
    if (len >= 4) {
      ssize_t ret = original_recvfrom(
          sockfd, buffer, 4, MSG_PEEK | MSG_DONTWAIT, src_addr, addrlen);
      if (strncmp(buffer, "hook", 4) == 0) {
        flag_recvfrom = 1;
        return 4;
      }
    }
    return original_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
  }

  if (flag_recvfrom == 1) {
    int needread = 0;

    if (first_read) {
      read_from_afl();  // 第一次需要从afl收到hook
      first_read = 0;

      needread = 1;
    } else if (need_seed) {  // 如果不是第一次但是需要种子则打开
      send_to_afl();
      read_from_afl();

      needread = 1;
    }

    if (seed_length > 0) {
      int   count = 0;
      FILE *num_file = fopen(NUM_FILENAME, "rb");
      if (!num_file) { perror("Open num_file for read failed"); }
      if (fread(&count, sizeof(count), 1, num_file) != 1) {
        perror("wrong in read");
        // exit(2);
      }
      fclose(num_file);
      num_file = NULL;
      if (count != orig_seed_length) {
        if (fp != NULL) {
          fclose(fp);
          fp = NULL;
        }
        needread = 1;
      }
    }

    if (needread) {
      fp = fopen(FILENAME, "rb");

      FILE *num_file = fopen(NUM_FILENAME, "r");
      if (!num_file) { perror("Open num_file for read failed"); }

      if (fread(&seed_length, sizeof(seed_length), 1, num_file) != 1) {
        perror("wrong in read");
      }
      fclose(num_file);
      num_file = NULL;

      orig_seed_length = seed_length;

      needread = 0;
    }

    int    total_bytes_received = 0;
    size_t buffer_size = 0;
    size_t bytes_read = 0;
    long   file_length;
    long   remaining_length;
    int    error_packet = 0;

    int real_read = 0;
    printf("len:%ld\n", len);

    static u8 *numfile_buffer = NULL;

    static u8 counted_length = 0;

    if (seed_length == 0) {
      error_packet = 1;

    } else if (seed_length <= len) {  // 此时我们需要新的seed

      real_read = fread(buf, sizeof(char), seed_length, fp);

      if (DEBUG) {
        printf("buf:\n");
        printf("real_read=%d\n", real_read);
        printHex(((char *)buf), real_read);
      }

      total_bytes_received += real_read;

      seed_length = 0;
    } else {  // len<seed_length

      real_read = fread(buf, sizeof(char), len, fp);

      if (DEBUG) {
        printf("buf:\n");
        printf("real_read=%d\n", real_read);
        printHex(((char *)buf), real_read);
      }

      total_bytes_received += real_read;

      seed_length -= (int)len;
    }

    if (len > 8096) {
      error_packet = 1;
      // exit(2);
    }

    printf("seed_length:%d\n", seed_length);

    need_seed = 0;
    if (feof(fp) || error_packet > 0 || seed_length == 0) {
      need_seed = 1;
      fclose(fp);
      fp = NULL;
      printf("need new seed\n");
    }

    // recvfrom need some manually crafted message

    set_manual_cliaddr((struct sockaddr_in *)src_addr);

    addrlen = sizeof((struct sockaddr_in *)src_addr);

    return total_bytes_received;
  }
}
typedef ssize_t (*orig_read_func_type)(int sockfd, void *buf, size_t count);
static orig_read_func_type original_read = NULL;
ssize_t   read(int fd, void *buf, size_t count) {
  // printf("read called here\n");
  if (!original_read) {
    original_read = (orig_read_func_type)dlsym(RTLD_NEXT, "read");
  }

  if (!original_recv) {
    original_recv = (orig_recv_func_type)dlsym(RTLD_NEXT, "recv");
  }

  int isNetworkSocket = sd_is_socket(fd, AF_UNSPEC, 0, 0);

  if (!isNetworkSocket) {
    return original_read(fd, buf, count);
  }

  if (flag_read == 0) {                                
    char    buffer[5];
    ssize_t ret = original_recv(fd, buffer, 4, MSG_PEEK | MSG_DONTWAIT);   //read没有peek需要借助recv

    if (strncmp(buffer, "hook", 4) == 0) {///收到hook从本地读取
      flag_read = 1;
      //hook_fd = fd;
    } else {
      return original_read(fd, buf, count);//来自网络但不是hook
    }
  }

  if (flag_read == 1) {  //&& fd == hook_fd

    int needread = 0;

    if (first_read) {
      read_from_afl();  // 第一次需要从afl收到hook
      first_read = 0;
      // need_reopen_input();    //第一次直接读，更新一下 last_num_cur_input
      needread = 1;
    } else if (need_seed) {  // 如果不是第一次但是需要种子则打开
      send_to_afl();
      read_from_afl();
      // need_reopen_input();    //更新一下 last_num_cur_input
      needread = 1;
    }

    if (seed_length > 0) {
      int   len = 0;
      FILE *num_file = fopen(NUM_FILENAME, "rb");
      if (!num_file) { perror("Open num_file for read failed"); }
      if (fread(&len, sizeof(len), 1, num_file) != 1) {
        perror("wrong in read");
        //exit(2);

      }
      fclose(num_file);
      num_file = NULL;

      if (len != orig_seed_length) { 
          if (fp != NULL) { 
              fclose(fp);
            fp = NULL;
          }
          needread = 1;

      }


    }

    if (needread) {
      printf("hook read numfile\n");

      fp = fopen(FILENAME, "rb");
      if (!fp) { perror("Open file for read failed"); }

      FILE *num_file = fopen(NUM_FILENAME, "r");
      if (!num_file) { perror("Open num_file for read failed"); }

      if (fread(&seed_length, sizeof(seed_length), 1, num_file) != 1) {
          perror("wrong in read");
      }
      fclose(num_file);
      printf("seed_length:%d\n", seed_length);

      orig_seed_length = seed_length;

      needread = 0;
    }

    

    int    total_bytes_received = 0;
    size_t buffer_size = 0;
    size_t bytes_read = 0;
    long   file_length;
    long   remaining_length;
    int    error_packet = 0;

    int real_read = 0;
    printf("count:%ld\n", count);

    static u8 *numfile_buffer = NULL;

    static u8 counted_length = 0;

    if (seed_length == 0) {
      error_packet = 1;

    } else if (seed_length <= count) {  // 此时我们需要新的seed

      real_read = fread(buf, sizeof(char), seed_length, fp);

      if (DEBUG) {
        printf("buf:\n");
        printf("real_read=%d\n", real_read);
        printHex(((char *)buf), real_read);
      }

      total_bytes_received += real_read;

      seed_length = 0;
    } else {  // count<seed_length

      real_read = fread(buf, sizeof(char), count, fp);

      if (DEBUG) {
        printf("buf:\n");
        printf("real_read=%d\n", real_read);
        printHex(((char *)buf), real_read);
      }

      total_bytes_received += real_read;

      seed_length -= (int)count;
    }

    if (count > 8096) { 
        error_packet = 1;
      //exit(2);
    }

    printf("seed_length:%d\n", seed_length);

    need_seed = 0;
    if (feof(fp) || error_packet > 0 || seed_length == 0) {
      need_seed = 1;
      fclose(fp);
      fp = NULL;
      printf("need new seed\n");
    }

    return total_bytes_received;
  }
  
}
typedef ssize_t (*orig_recvmsg_func_type)(int sockfd, struct msghdr *msg, int flags);
// original recvmsg
static orig_recvmsg_func_type original_recvmsg = NULL;
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  if (!original_recvmsg) {
    original_recvmsg = (orig_recvmsg_func_type)dlsym(RTLD_NEXT, "recvmsg");
  }

  int check_valid = is_valid_socket(sockfd);
  // printf("%d\n", check_valid);
  // printf("recvmsg, msg.msg_iovlen=%ld, msg.msg_iov[0].iov_len=%ld \n",
  // msg->msg_iovlen,
  //     msg->msg_iov[0].iov_len);
  char buffer[5];
  int  isNetworkSocket = sd_is_socket(sockfd, AF_UNSPEC, 0, 0);
  if (!isNetworkSocket) {
    // printf("not network:%d\n",isNetworkSocket);
    return original_recvmsg(sockfd, msg, flags);
  }
  if (flag_recvmsg == 0) {
    struct msghdr my_msg = {0};
    struct iovec  iov[1];
    iov[0].iov_base = buffer;
    iov[0].iov_len = 4;
    my_msg.msg_iov = iov;
    my_msg.msg_iovlen = 1;
    ssize_t bytesReceived =
        original_recvmsg(sockfd, &my_msg, MSG_DONTWAIT | MSG_PEEK);
    buffer[4] = '\0';
    // printf("original_recvmsg called bytesReceived=%ld %#08x, %d\n",
    //    bytesReceived, *(int*)(buffer), buffer[1]);
    // printf("%s\n", buffer);
    if (strncmp(buffer, "hook", 4) == 0) {
      printf("flag_recvmsg==1\n");
      flag_recvmsg = 1;
      return 4;
    } else {
      return original_recvmsg(sockfd, msg, flags);
    }
  }

  if (flag_recvmsg == 1) {
    int needread = 0;
    int total_bytes_received = 0;

    if (first_read) {
      read_from_afl();  // 第一次需要从afl收到hook
      first_read = 0;
      // need_reopen_input();    //第一次直接读，更新一下 last_num_cur_input
      needread = 1;
    } else if (need_seed) {  // 如果不是第一次但是需要种子则打开
      send_to_afl();
      read_from_afl();
      // need_reopen_input();    //更新一下 last_num_cur_input
      needread = 1;
    }

    if (seed_length > 0) {
      int   len = 0;
      FILE *num_file = fopen(NUM_FILENAME, "rb");
      if (!num_file) { perror("Open num_file for read failed"); }
      if (fread(&len, sizeof(len), 1, num_file) != 1) {
        perror("wrong in read");
        // exit(2);
      }
      fclose(num_file);
      num_file = NULL;

      if (len != orig_seed_length) {
        if (fp != NULL) {
            fclose(fp);
            fp = NULL;
        }
        needread = 1;
      }
    }

    if (needread) {
      printf("hook read numfile\n");

      fp = fopen(FILENAME, "rb");
      if (!fp) { perror("Open file for read failed"); }

      FILE *num_file = fopen(NUM_FILENAME, "r");
      if (!num_file) { perror("Open num_file for read failed"); }

      if (fread(&seed_length, sizeof(seed_length), 1, num_file) != 1) {
        perror("wrong in read");
      }
      fclose(num_file);
      num_file = NULL;
      printf("seed_length:%d\n", seed_length);

      orig_seed_length = seed_length;

      needread = 0;
    }

    int error_packet = 0;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(10001);  // 将主机字节序转换为网络字节序
    inet_pton(AF_INET, "127.0.0.1", &(target_addr.sin_addr));

    memcpy(msg->msg_name, &target_addr, sizeof(struct sockaddr_in));
    msg->msg_namelen = sizeof(struct sockaddr_in);

    struct ifreq ifr;

    struct in_pktinfo ip_pktinfo_value;
    ip_pktinfo_value.ipi_spec_dst.s_addr = inet_addr("127.0.0.1");
    ip_pktinfo_value.ipi_ifindex = 1;

    char            control_buffer[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct cmsghdr *cmptr = (struct cmsghdr *)control_buffer;
    cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    cmptr->cmsg_level = IPPROTO_IP;
    cmptr->cmsg_type = IP_PKTINFO;
    // 将数据拷贝到msg.msg_control中

    memcpy(CMSG_DATA(cmptr), &ip_pktinfo_value, sizeof(struct in_pktinfo));
    msg->msg_control = control_buffer;
    msg->msg_controllen = cmptr->cmsg_len;

    ssize_t len = 0;
    for (int i = 0; i < msg->msg_iovlen; i++) {
      len += msg->msg_iov[i].iov_len;
    }

   char *buf = (char *)malloc(len);
    int real_read = 0;

    if (seed_length == 0) {
      error_packet = 1;

    } else if (seed_length <= len) {  // 此时我们需要新的seed

      real_read = fread(buf, sizeof(char), seed_length, fp);

      if (DEBUG) {
        // printf("buf:\n");
        // printf("real_read=%d\n", real_read);
        printHex(((char *)buf), real_read);
      }

      total_bytes_received += real_read;

      seed_length = 0;
    } else {  // len<seed_length

      real_read = fread(buf, sizeof(char), len, fp);

      if (DEBUG) {
        // printf("buf:\n");
        // printf("real_read=%d\n", real_read);
        printHex(((char *)buf), real_read);
      }

      total_bytes_received += real_read;

      seed_length -= (int)len;
    }

    msg->msg_iov->iov_base = buf;    
    msg->msg_iov->iov_len = sizeof(buf); 

    if (len > 8096) {
      error_packet = 1;
      // exit(2);
    }

    // printf("seed_length:%d\n", seed_length);

    need_seed = 0;
    if (feof(fp) || error_packet > 0 || seed_length == 0) {
      need_seed = 1;
      fclose(fp);
      fp = NULL;
      // printf("need new seed\n");
    }

    return total_bytes_received;
  }
}

void send_to_afl() {
  printf("send to afl success  fd:%d\n", FORKSRV_FD + 4);
  if (write(FORKSRV_FD + 4, FINIREAD, 4) < 0) {
    perror("wrong in writing to afl-fuzz ");
    //_exit(1);
  }
   
}
void read_from_afl() {
  if (!original_read) {
    original_read = (orig_read_func_type)dlsym(RTLD_NEXT, "read");
  }
  char buf[4];
  int  res = 0;
  if ((res = original_read(FORKSRV_FD + 3, buf, 4)) < 0) {
    perror("Don't recv hello?(OOM?)read_from_afl:");
    //_exit(1);
  }
   printf("read from afl success fd:%d\n",FORKSRV_FD+3);
}
int close(int fd) {
  if (fd == FORKSRV_FD + 3 || fd == FORKSRV_FD + 4) { return 0; }
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
void thread_handler(union sigval val) {
    send_to_afl();
    timer_delete(timerid);
}


void set_manual_cliaddr(struct sockaddr_in * cliaddr) {
    cliaddr->sin_family = AF_INET;
    cliaddr->sin_port = htons(10000);  // Client's port number, change if needed
    inet_pton(AF_INET, "127.0.0.1",
              &(cliaddr->sin_addr));  // Client's IP address
}