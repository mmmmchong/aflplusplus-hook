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
#include <errno.h>
#include <stdarg.h>
#include<poll.h>
#include <sys/select.h>
#include <sys/shm.h>


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
#define FD_CLOSED "2222"



int   shm_id = 0;       //shm id用于shm 访问
unsigned char *shared_memory=NULL;

static int    flag_recvmsg = 0;
static int    flag_recvfrom = 0;
static int    flag_read = 0;
static int    flag_recv = 0;
static int    first_read = 1;

int accepted = 0;
int listened_fd = 0;
int srv_fd = 0;  // 建立连接的fd
int           hook_fd;                           // 需要hook的fd


static unsigned int       cur_seed_length = 0;       //seed length
static unsigned int       orig_seed_length = 0;       // seed length
static unsigned int       readed_length = 0;    //length haved readed

static int      need_seed = 1;
static FILE     *fp;

struct epoll_event *ev;

// 用于存储首次调用 getsockname 时的数据
static struct sockaddr_storage saved_sock_addr;
static socklen_t               saved_sock_addrlen = 0;
static int sock_saved = 0;  // 用于标记是否已保存数据

static struct sockaddr_storage saved_peer_addr;
static socklen_t               saved_peer_addrlen = 0;
static int peername_saved = 0;  // 用于标记是否已保存数据

void  send_to_afl();
void  read_from_afl();

void get_length();
void set_manual_cliaddr(struct sockaddr_in *cliaddr);
int  get_shm_id();
int  is_valid_socket(int fd);


void          printHex(const char *buf, int len) {
  for (int i = 0; i < len; i++) {
    printf("%02X ", (unsigned char)buf[i]);
  }
  printf("\n");
}

/*
__attribute__((constructor)) void hook_init() {
  char cwd[1024];  // Buffer to hold the current working directory
  if (getcwd(cwd, sizeof(cwd)) == NULL) {
    perror("getcwd() error");
    exit(-1);
  }

  const char *base_dir =
      "/default";  // Assuming you still want to append this directory
  const char *cur_input_file = "/.cur_input";
  const char *num_cur_input_file = "/.num_cur_input";

  size_t filename_size =
      strlen(cwd) + strlen(base_dir) + strlen(cur_input_file) + 1;
  size_t numfilename_size =
      strlen(cwd) + strlen(base_dir) + strlen(num_cur_input_file) + 1;

  char *FILENAME = malloc(filename_size);
  char *NUM_FILENAME = malloc(numfilename_size);
  if (FILENAME && NUM_FILENAME) {
    snprintf(FILENAME, filename_size, "%s%s%s", cwd, base_dir, cur_input_file);
    snprintf(NUM_FILENAME, numfilename_size, "%s%s%s", cwd, base_dir,
             num_cur_input_file);
    if (DEBUG) printf("%s\n%s\n", FILENAME, NUM_FILENAME);
    

  } else {
    fprintf(stderr, "Error: Memory allocation failed.\n");
    exit(-1);
  }
  if (DEBUG) {
    printf("Current input file set to %s\n", FILENAME);
    printf("Number of current input file set to %s\n", NUM_FILENAME);
  }
  // Remember to free FILENAME and NUM_FILENAME at the appropriate place in your
  // code
}
*/
/*
__attribute__((constructor)) void hook_init() {
  const char *output_file = getenv("OUTPUT_FILE");
  if (output_file) {
    size_t filename_size =
        strlen(output_file) + strlen("/default/.cur_input") + 1;
    size_t numfilename_size =
        strlen(output_file) + strlen("/default/.num_cur_input") + 1;

    FILENAME = malloc(filename_size);
    NUM_FILENAME = malloc(numfilename_size);
    if (FILENAME && NUM_FILENAME) {
      snprintf(FILENAME, filename_size, "%s/default/.cur_input", output_file);
      snprintf(NUM_FILENAME, numfilename_size, "%s/default/.num_cur_input",
               output_file);
    } else {
      fprintf(stderr, "Error: Memory allocation failed.\n");
    }
  } else {
    fprintf(stderr, "Error: OUTPUT_FILE environment variable not set.\n");
    exit(-1);
  }

  printf("set output file %s", output_file);
}
*/

__attribute__((constructor)) void hook_clean_up() {
  if (srv_fd > 0) { close(srv_fd); }
  if (shared_memory!=NULL) {
      shmdt(shared_memory); 
  }
}

/* int need_reopen_input() {
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

}*/

typedef int (*orig_select_type)(int nfds, fd_set *readfds, fd_set *writefds,
                                fd_set *exceptfds, struct timeval *timeout);

orig_select_type orig_select = NULL;

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout) {
  if (!orig_select) {
    orig_select = (orig_select_type)dlsym(RTLD_NEXT, "select");
  }

  if (accepted == 1) {
    if (readfds) {
      for (int fd = 0; fd < nfds; fd++) {
        if (FD_ISSET(fd, readfds)) {
          FD_ZERO(readfds);
          FD_SET(fd, readfds);
          return 1;  
        }
      }
    }
    errno = EINVAL;
    return -1;
  }

  return orig_select(nfds, readfds, writefds, exceptfds, timeout);
}

typedef int (*orig_poll_type)(struct pollfd fds[], nfds_t nfds, int timeout);

orig_poll_type orig_poll = NULL;

int poll(struct pollfd fds[], nfds_t nfds, int timeout) {
  if (!orig_poll) { orig_poll = (orig_poll_type)dlsym(RTLD_NEXT, "poll"); }

  if (accepted) {
      for (int i = 0; i < nfds; i++) {
      if (fds[i].fd == srv_fd ) { 
              fds[i].revents = POLLIN;
        printf("\n\n\npoll hooked!\n\n\n\n");
      }
    }

  } else {
    return orig_poll(fds, nfds, timeout);
  }
  return 1;
  
}


typedef int (*orig_epoll_ctl_type)(int, int, int, struct epoll_event *);

orig_epoll_ctl_type orig_epoll_ctl = NULL;

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
  if (!orig_epoll_ctl) {
    orig_epoll_ctl = (orig_epoll_ctl_type)dlsym(RTLD_NEXT, "epoll_ctl");
  }

  if (accepted && op == EPOLL_CTL_ADD) {
    printf("save epoll event\n");
    ev = event;

    return orig_epoll_ctl(epfd, op, fd, event);

  } else {
    return orig_epoll_ctl(epfd, op, fd, event);
  }
}
typedef int (*original_epoll_wait_type)(int epfd, struct epoll_event *events, int maxevents, int timeout);
original_epoll_wait_type original_epoll_wait = NULL;
int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                 int timeout) {
    if (!original_epoll_wait) {
      original_epoll_wait =
          (original_epoll_wait_type)dlsym(RTLD_NEXT, "epoll_wait");
    }

    //return original_epoll_wait(epfd, events, maxevents, timeout);

    if (maxevents < 1) { return -1; }

    if (accepted) {  // 连接还在，没有被移除，此时可以继续返回读

      printf("srv_fd :%d,accepted?:%d\n", srv_fd, accepted);

      *events = *ev;

      return 1;
    }
    return original_epoll_wait(epfd, events, maxevents, timeout);
}


typedef ssize_t (*orig_recv_func_type)(int sockfd, void *buf, size_t len,
                                       int flags);
orig_recv_func_type original_recv = NULL;
ssize_t __attribute__((hot))
recv(int sockfd, void *buf, size_t len, int flags) {

  if (!original_recv) {
    original_recv = (orig_recv_func_type)dlsym(RTLD_NEXT, "recv");
  }

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

    int need_length = 0;

    if (first_read) {

      read_from_afl();  // 第一次需要从afl收到hook

      first_read = 0;

      // need_reopen_input();    //第一次直接读，更新一下 last_num_cur_input

      need_length = 1;

    } else if (need_seed) {  // 如果不是第一次但是需要种子则打开

      send_to_afl();

      read_from_afl();

      // need_reopen_input();    //更新一下 last_num_cur_input

      need_length = 1;
    }

    if (!shm_id)  shm_id = get_shm_id();
    
     shared_memory = shmat(shm_id, NULL, 0);

    if (shared_memory == (void *)-1) {

      perror("shmat failed");

      return -1;

    }


    if (orig_seed_length > 0 && !need_length) {

      size_t check = *(size_t *)shared_memory;

      if (check != orig_seed_length) {
            
           need_length = 1;
            
      }

    }

    if (need_length) {

      orig_seed_length=cur_seed_length = *(size_t *)shared_memory;
      
      if ((int)orig_seed_length == -1) {

          printf("disconnected!\n");

          if (shmdt(shared_memory) == -1) {
          perror("shmdt failed");

          return -1;
        }

          return 0; 
      }

      need_length = 0;

    }
   
    int error_packet = 0;

    int real_read = 0;

    u32 offset = orig_seed_length - cur_seed_length+sizeof(size_t); //需要加上sizeof(size_t)是因为共享内
                                                                    //存开头表示的是长度，之后才是种子
    if (cur_seed_length == 0) {

      error_packet = 1;

    } else if (cur_seed_length <= len) {  // 此时我们需要新的seed

      memcpy(buf, shared_memory + offset, cur_seed_length);

      if (DEBUG) printHex(((char *)buf), cur_seed_length);

      real_read = cur_seed_length;

      cur_seed_length = 0;

    } else {  // len<seed_length

      memcpy(buf, shared_memory + offset, len);

      if (DEBUG) printHex(((char *)buf), readed_length);

      cur_seed_length -= (int)len;

      real_read = len;

    }

      if (real_read > 8096) {
      error_packet = 1;
      // exit(2);
    }

    if (shmdt(shared_memory) == -1) { 
        
        perror("shmdt failed"); 
    
        return -1;
    }

    need_seed = 0;

    if ( error_packet > 0 || cur_seed_length == 0)   need_seed = 1;

    return real_read;

  }
}


typedef ssize_t (*recvfrom_t)(int sockfd, void *buf, size_t len, int flags,
                              struct sockaddr *src_addr, socklen_t *addrlen);
static recvfrom_t original_recvfrom = NULL;
ssize_t __attribute__((hot))
recvfrom(int sockfd, void *buf, size_t len, int flags,
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
    int need_length = 0;

    if (first_read) {
      read_from_afl();  // 第一次需要从afl收到hook
      first_read = 0;

      need_length = 1;
    } else if (need_seed) {  // 如果不是第一次但是需要种子则打开
      send_to_afl();
      read_from_afl();

      need_length = 1;
    }

   
    if (!shm_id) shm_id = get_shm_id();

    shared_memory = shmat(shm_id, NULL, 0);

    //printHex((char *)shared_memory, 5);

    if (shared_memory == (void *)-1) {

      printf("shm_id:%d\n", (shm_id));

      perror("shmat failed");

      return -1;
    }

    if (orig_seed_length > 0 && !need_length) {
      size_t check = *(size_t *)shared_memory;

      if (check != orig_seed_length) { need_length = 1; }
    }

    if (need_length) {
      orig_seed_length = cur_seed_length = *(size_t *)shared_memory;

      if ((int)orig_seed_length == -1) { 
          
          printf("disconnected!\n");

          if (shmdt(shared_memory) == -1) {
          perror("shmdt failed");

          return -1;
        }

          return 0; }

      need_length = 0;
    }

    int error_packet = 0;

    int real_read = 0;


    u32 offset = orig_seed_length - cur_seed_length +
                 sizeof(size_t);  // 需要加上sizeof(size_t)是因为共享内
                                  // 存开头表示的是长度，之后才是种子

    if (cur_seed_length == 0) {
      error_packet = 1;

    } else if (cur_seed_length <= len) {  // 此时我们需要新的seed

      memcpy((char*)buf, shared_memory + offset, cur_seed_length);

      //printHex(((char *)shared_memory ), orig_seed_length);
      //printHex(((char *)buf), orig_seed_length);

      real_read = cur_seed_length;

      cur_seed_length = 0;

    } else {  // len<seed_length

      memcpy((char*)buf, shared_memory + offset, len);

      //printHex(((char *)shared_memory), orig_seed_length);
      //printHex(((char *)buf), readed_length);

      cur_seed_length -= (int)len;

      real_read = len;
    }

    if (shmdt(shared_memory) == -1) {
      perror("shmdt failed");

      return -1;
    }

    printf("real read:%d\n", real_read);

    need_seed = 0;

    set_manual_cliaddr((struct sockaddr_in *)src_addr);

    socklen_t actual_addrlen = sizeof(struct sockaddr_in);
    addrlen = &actual_addrlen;  


    if (error_packet > 0 || cur_seed_length == 0) need_seed = 1;

    return real_read;
  }
}
typedef ssize_t (*orig_read_func_type)(int sockfd, void *buf, size_t count);
static orig_read_func_type original_read = NULL;
ssize_t __attribute__((hot)) read(int fd, void *buf, size_t count) {
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

     // if (srv_fd != fd)  return original_read(fd, buf, count);
    
    int need_length = 0;

    if (first_read) {
      read_from_afl();  // 第一次需要从afl收到hook
      first_read = 0;
      // need_reopen_input();    //第一次直接读，更新一下 last_num_cur_input
      need_length = 1;
    } else if (need_seed) {  // 如果不是第一次但是需要种子则打开
      send_to_afl();
      read_from_afl();
      // need_reopen_input();    //更新一下 last_num_cur_input
      need_length = 1;
    }

   
    if (!shm_id) shm_id = get_shm_id();

    shared_memory = shmat(shm_id, NULL, 0);

    if (shared_memory == (void *)-1) {
      perror("shmat failed");

      return -1;
    }

    if (orig_seed_length > 0 && !need_length) {
      size_t check = *(size_t *)shared_memory;

      if (check != orig_seed_length) { need_length = 1; }
    }

    if (need_length) {
      orig_seed_length = cur_seed_length = *(size_t *)shared_memory;

      if ((int)orig_seed_length == -1) {
          
          printf("disconnected!\n");

          if (shmdt(shared_memory) == -1) {
          perror("shmdt failed");

          return -1;
          }

          return 0; }

      need_length = 0;
    }

    int error_packet = 0;

    int real_read = 0;

    u32 offset = orig_seed_length - cur_seed_length +
                 sizeof(size_t);  // 需要加上sizeof(size_t)是因为共享内
                                  // 存开头表示的是长度，之后才是种子
    if (cur_seed_length == 0) {
      error_packet = 1;

    } else if (cur_seed_length <= count) {  // 此时我们需要新的seed

      memcpy(buf, shared_memory + offset, cur_seed_length);

      if (DEBUG) printHex(((char *)buf), cur_seed_length);

      real_read = cur_seed_length;

      cur_seed_length = 0;

    } else {  // len<seed_length

      memcpy(buf, shared_memory + offset, count);

      if (DEBUG) printHex(((char *)buf), readed_length);

      cur_seed_length -= (int)count;

      real_read = count;
    }

    if (real_read > 8096) {
      error_packet = 1;
      // exit(2);
    }

    if (shmdt(shared_memory) == -1) {
      perror("shmdt failed");

      return -1;
    }

    need_seed = 0;

    if (error_packet > 0 || cur_seed_length == 0) need_seed = 1;

    return real_read;
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
    int need_length = 0;
    int total_bytes_received = 0;

    if (first_read) {
      read_from_afl();  // 第一次需要从afl收到hook
      first_read = 0;
      // need_reopen_input();    //第一次直接读，更新一下 last_num_cur_input
      need_length = 1;
    } else if (need_seed) {  // 如果不是第一次但是需要种子则打开
      send_to_afl();
      read_from_afl();
      // need_reopen_input();    //更新一下 last_num_cur_input
      need_length = 1;
    }

   
    if (!shm_id) shm_id = get_shm_id();

    shared_memory = shmat(shm_id, NULL, 0);

    if (shared_memory == (void *)-1) {

        printf("shm_id:%d\n", shm_id);

      perror("shmat failed");

      return -1;
    }


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

  if (orig_seed_length > 0 && !need_length) {

    size_t check = *(size_t *)shared_memory;

    if (check != orig_seed_length) { need_length = 1; }

 }

 if (need_length) {

      orig_seed_length = cur_seed_length = *(size_t *)shared_memory;

      if ((int)orig_seed_length == -1) { 
          
          printf("disconnected!\n");

          if (shmdt(shared_memory) == -1) {
          perror("shmdt failed");

          return -1;
          }

          return 0; }

      need_length = 0;
   }
 
  int error_packet = 0;

  int real_read = 0; 

   u32 offset = orig_seed_length - cur_seed_length +
               sizeof(size_t);  // 需要加上sizeof(size_t)是因为共享内
                                // 存开头表示的是长度，之后才是种子

      if (cur_seed_length == 0) {
      error_packet = 1;

   } else if (cur_seed_length <= len) {  // 此时我们需要新的seed

      memcpy(buf, shared_memory + offset, cur_seed_length);


      if (DEBUG) printHex(((char *)buf), cur_seed_length);

      real_read = cur_seed_length;

      cur_seed_length = 0;

   } else {  // len<seed_length

      memcpy(buf, shared_memory + offset, len);

      if (DEBUG) printHex(((char *)buf), readed_length);

      cur_seed_length -= (int)len;

      real_read = len;
   }

   if (DEBUG)
   printf("real read:%d\n", real_read);

    msg->msg_iov->iov_base = buf;    
    msg->msg_iov->iov_len = sizeof(buf); 

    if (real_read > 8096) {
      error_packet = 1;
      // exit(2);
    }

    if (shmdt(shared_memory) == -1) {
      perror("shmdt failed");

      return -1;
    }

    need_seed = 0;

    if (error_packet > 0 || cur_seed_length == 0) { need_seed = 1; }

    return real_read;


  }
}

void send_to_afl() {
  
  if (write(FORKSRV_FD + 4, FINIREAD, 4) < 0) {
    perror("wrong in writing to afl-fuzz ");
    //_exit(1);
  }

  printf("send to afl success  fd:%d\n", FORKSRV_FD + 4);

}
void read_from_afl() {
  if (!original_read) {
    original_read = (orig_read_func_type)dlsym(RTLD_NEXT, "read");
  }

  char buf[4];
  int  res = 0;
  int  bytesRead;
   if ((res = original_read(FORKSRV_FD + 3, buf, 4)) < 0) {
    perror("Don't recv hello?(OOM?)read_from_afl:");
    //_exit(1);
  }

    fcntl(FORKSRV_FD + 3, F_SETFL, O_NONBLOCK);

    while (1) {
    bytesRead = original_read(FORKSRV_FD + 3, buf, 1);
    if (bytesRead < 0) { 
        int flags = fcntl(FORKSRV_FD + 3, F_GETFL);
      fcntl(FORKSRV_FD + 3, F_SETFL, flags & ~O_NONBLOCK);
        break;
    }

    }


   printf("read from afl success fd:%d\n",FORKSRV_FD+3);
}
/*
typedef int (*orig_listen_type)(int sockfd, int backlog);

orig_listen_type orig_listen;

int listen(int sockfd, int backlog) {
   if (!orig_listen) {
    orig_listen = (orig_listen_type)dlsym(RTLD_NEXT, "listen");
   }
   if (DEBUG)
   printf("Hooked listen called with sockfd: %d\n", sockfd);

   listened_fd = sockfd;

   return orig_listen(sockfd, backlog);
}

*/

typedef int (*orig_accept_type)(int, struct sockaddr *, socklen_t *);

orig_accept_type orig_accept;


typedef int (*orig_accept4_type)(int, struct sockaddr *, socklen_t *, int);

orig_accept4_type orig_accept4;

/*
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
   if (!orig_accept) {
    orig_accept = (orig_accept_type)dlsym(RTLD_NEXT, "accept");
   }

   // printf("accept hererererer\n");
   if (listened_fd == sockfd && !accepted) {
    printf("sockfd:%d\n", sockfd);

    srv_fd = orig_accept(sockfd, addr, addrlen);


    if (srv_fd >= 0) {
        printf("accept successful fd: %d\n", srv_fd);
        accepted = 1;
        getsockname(sockfd, (struct sockaddr *)&saved_sock_addr,
                    &saved_sock_addrlen);
        getpeername(srv_fd, (struct sockaddr *)&saved_peer_addr,
                    &saved_peer_addrlen);


    } else{
        perror("accept failed\n");
        return -1;
    }

    return 10001;
   } else if (accepted) {

    return 10001;
   } else {
    return orig_accept(sockfd, addr, addrlen);
   }
}


int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
   if (!orig_accept4) {
    orig_accept4 = (orig_accept4_type)dlsym(RTLD_NEXT, "accept4");
   }

   printf("accepted? :%d\n", accepted);
   // printf("accept hererererer\n");
   if (listened_fd == sockfd && !accepted) {
    printf("sockfd:%d\n", sockfd);

    srv_fd = orig_accept4(sockfd, addr, addrlen,flags);

    if (srv_fd >= 0) {
        printf("accept4 successful fd: %d\n", srv_fd);
        accepted = 1;
        getsockname(sockfd, (struct sockaddr *)&saved_sock_addr,
                    &saved_sock_addrlen);
        getpeername(srv_fd, (struct sockaddr *)&saved_peer_addr,
                    &saved_peer_addrlen);

    } else {
        perror("accept4 failed\n");
        return -1;
    }

    return 10001;
   } else if (accepted) {
    return 10001;
   } else {
    return orig_accept4(sockfd, addr, addrlen,flags);
   }
}*/

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
   if (!orig_accept4) {
    orig_accept4 = (orig_accept4_type)dlsym(RTLD_NEXT, "accept4");
   }

   if (srv_fd) { 
       close(srv_fd);
   }


    srv_fd = orig_accept4(sockfd, addr, addrlen, flags);
   first_read = 1;

    return srv_fd;
} 

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
   if (!orig_accept) {
    orig_accept = (orig_accept_type)dlsym(RTLD_NEXT, "accept");
   }

   if (srv_fd) { 
       close(srv_fd);
   }

    srv_fd = orig_accept(sockfd, addr, addrlen);
   first_read = 1;

    return srv_fd;
}


typedef int (*orig_close_type)(int);

orig_close_type orig_close;
/*
int close(int fd) {
   if (fd == FORKSRV_FD + 3 || fd == FORKSRV_FD + 4) { return 0; }
  
   if (!orig_close) {
    orig_close = (orig_close_type)dlsym(RTLD_NEXT, "close");
   }

   if (fd == srv_fd) {
    printf("at close\n");
    srv_fd = 0;
    printf("send to afl success  fd:%d,data:%d\n", FORKSRV_FD + 4, FD_CLOSED);
    if (write(FORKSRV_FD + 4, FD_CLOSED, 4) < 0) {
        perror("wrong in writing to afl-fuzz ");
        //_exit(1);

    }

    accepted = 0;

    return orig_close(fd);
   } else if (fd == 10001) {
    return 0;
   }

  // return original_close(fd);
}*/

int close(int fd) {
    if (fd == FORKSRV_FD + 3 || fd == FORKSRV_FD + 4 || fd == FORKSRV_FD +10) {
    return 0;
    }

    if (!orig_close) {
    orig_close = (orig_close_type)dlsym(RTLD_NEXT, "close");
    }
    if (fd == srv_fd) {
    printf("at close\n");
    srv_fd = 0;
   
    if (write(FORKSRV_FD + 4, FD_CLOSED, 4) < 0) {
        perror("wrong in writing to afl-fuzz ");
        //_exit(1);
        }
    }
    accepted = 0;
    first_read = 1;
    return orig_close(fd);
   }

int is_valid_socket(int fd) {
  // 使用 F_GETFL 标志获取文件描述符状态
  int flags = fcntl(fd, F_GETFL);

  // 如果 fcntl 成功执行，说明文件描述符是有效的
  return (flags != -1);
}


void set_manual_cliaddr(struct sockaddr_in * cliaddr) {
    cliaddr->sin_family = AF_INET;
    cliaddr->sin_port = htons(10000);  // Client's port number, change if needed
    inet_pton(AF_INET, "127.0.0.1",
              &(cliaddr->sin_addr));  // Client's IP address
}

int (*original_dup)(int) = NULL;

int dup(int fd) {

    if (!original_dup) { original_dup = dlsym(RTLD_NEXT, "dup"); }


    if (fd == srv_fd && srv_fd>0) {

    int new_fd=original_dup(fd);

        printf("dup!: %d->%d\n", fd, new_fd);

        srv_fd = new_fd;

    return new_fd;
    } else {
    return original_dup(fd);
    }

}

int (*original_dup2)(int,int) = NULL;
   int dup2(int oldfd, int newfd) {
    if (!original_dup2) { original_dup2 = dlsym(RTLD_NEXT, "dup2"); }

    if (oldfd == srv_fd && srv_fd > 0) { 

        int new = original_dup2(oldfd, newfd);

         printf("dup!: %d->%d\n", oldfd, new);


    if (new > 0)
        srv_fd = new;
    else
        return new;
    } else {
    return original_dup2(oldfd, newfd);
    ;
    }
   }

int (*original_dup3)(int, int,int) = NULL;
int dup3(int oldfd, int newfd, int flags) {
    if (!original_dup3) { original_dup3 = dlsym(RTLD_NEXT, "dup3"); }
    if (oldfd == srv_fd && srv_fd > 0) {
    int new = original_dup3(oldfd, newfd,flags);

    printf("dup!: %d->%d\n", oldfd, new);

    if (new > 0)
        srv_fd = new;
    else
        return new;
    } else {
    return original_dup3(oldfd, newfd, flags);
    
    }

   }

int get_shm_id() {
    char shm_id_str[10];

    memset(shm_id_str, 0, sizeof(shm_id_str));

    read(FORKSRV_FD + 10, shm_id_str, sizeof(shm_id_str) - 1);

    if (!shm_id_str) {
    fprintf(stderr, "Environment variable SHM_FUZZ_ENV_VAR not set.\n");
    exit(EXIT_FAILURE);
    } else {
    write(FORKSRV_FD +11, shm_id_str, strlen(shm_id_str));  
    }

    if (DEBUG) printf("shm_id:%d\n", atoi(shm_id_str));

    return atoi(shm_id_str);
   }





/*
typedef int (*orig_getpeername_type)(int sockfd, struct sockaddr *addr,
                                        socklen_t *addrlen);

   int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    orig_getpeername_type orig_getpeername;
    orig_getpeername = (orig_getpeername_type)dlsym(RTLD_NEXT, "getpeername");

    if (!peername_saved) {
    // 如果尚未保存数据，调用原始的 getpeername 并保存结果
    int result = orig_getpeername(sockfd, addr, addrlen);
    if (result == 0) {  // 仅当成功时保存数据
        memcpy(&saved_peer_addr, addr, *addrlen);
        saved_peer_addrlen = *addrlen;
        peername_saved = 1;
    }
    return result;
    } else {
    // 如果已保存数据，处理缓冲区大小问题并返回之前保存的数据
    if (*addrlen < saved_peer_addrlen) {
        // 如果提供的缓冲区太小，则根据地址类型截断数据
        if (saved_peer_addr.ss_family == AF_INET &&
            *addrlen >= sizeof(struct sockaddr_in)) {
        // 对于 IPv4 地址，确保至少有足够的空间存储 sockaddr_in 结构
        memcpy(addr, &saved_peer_addr, sizeof(struct sockaddr_in));
        *addrlen = sizeof(struct sockaddr_in);
        } else if (saved_peer_addr.ss_family == AF_INET6 &&
                   *addrlen >= sizeof(struct sockaddr_in6)) {
        // 对于 IPv6 地址，确保至少有足够的空间存储 sockaddr_in6 结构
        memcpy(addr, &saved_peer_addr, sizeof(struct sockaddr_in6));
        *addrlen = sizeof(struct sockaddr_in6);
        } else {
        // 如果连基本的地址结构都无法完全复制，则返回错误
        return -1;
        }
    } else {
        // 如果提供的缓冲区足够大，则复制整个地址
        memcpy(addr, &saved_peer_addr, saved_peer_addrlen);
        *addrlen = saved_peer_addrlen;
    }
    return 0;  // 成功返回
    }
   }

   typedef int (*orig_getsockname_type)(int sockfd, struct sockaddr *addr,
                                        socklen_t *addrlen);

   int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    orig_getsockname_type orig_getsockname;
    orig_getsockname = (orig_getsockname_type)dlsym(RTLD_NEXT, "getsockname");

    if (!sock_saved) {
    // 如果尚未保存数据，调用原始的 getsockname 并保存结果
    int result = orig_getsockname(sockfd, addr, addrlen);
    if (result == 0) {  // 仅当成功时保存数据
        memcpy(&saved_sock_addr, addr, *addrlen);
        saved_sock_addrlen = *addrlen;
        sock_saved = 1;
    }
    return result;
    } else {
    // 如果已保存数据，处理缓冲区大小问题并返回之前保存的数据
    if (*addrlen < saved_sock_addrlen) {
        // 如果提供的缓冲区太小，则根据地址类型截断数据
        if (saved_sock_addr.ss_family == AF_INET &&
            *addrlen >= sizeof(struct sockaddr_in)) {
        memcpy(addr, &saved_sock_addr, sizeof(struct sockaddr_in));
        *addrlen = sizeof(struct sockaddr_in);
        } else if (saved_sock_addr.ss_family == AF_INET6 &&
                   *addrlen >= sizeof(struct sockaddr_in6)) {
        memcpy(addr, &saved_sock_addr, sizeof(struct sockaddr_in6));
        *addrlen = sizeof(struct sockaddr_in6);
        } else {
        return -1;  // 如果连基本的地址结构都无法完全复制，则返回错误
        }
    } else {
        // 如果提供的缓冲区足够大，则复制整个地址
        memcpy(addr, &saved_sock_addr, saved_sock_addrlen);
        *addrlen = saved_sock_addrlen;
    }
    return 0;  // 成功返回
    }
   }


typedef int (*orig_setsockopt_type)(int sockfd, int level, int optname,
                                       const void *optval, socklen_t optlen);

   int setsockopt(int sockfd, int level, int optname, const void *optval,
                  socklen_t optlen) {
    static orig_setsockopt_type orig_setsockopt;
    if (!orig_setsockopt) {
    orig_setsockopt = (orig_setsockopt_type)dlsym(RTLD_NEXT, "setsockopt");
    }
    if (sockfd == srv_fd) {
    printf("Hooked setsockopt called with sockfd = %d\n", sockfd);
    return 0;
    } else {
    return orig_setsockopt(sockfd, level, optname, optval, optlen);
    }
   }


typedef int (*original_fcntl_type)(int, int, ...);
original_fcntl_type original_fcntl;

int fcntl(int fd, int cmd, ...) {
    if (!original_fcntl) {
    // 使用 dlsym 获取原始 fcntl 函数的指针
    original_fcntl = (original_fcntl_type)dlsym(RTLD_NEXT, "fcntl");
    if (!original_fcntl) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
        return -1;
    }
    }

    va_list args;
    va_start(args, cmd);
    void *arg = va_arg(args, void *);
    va_end(args);

    if (fd == 10001) { return original_fcntl(fd, cmd, arg); }
}*/