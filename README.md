# aflplusplus-hook

### 目前的输出：

可以正常运行，执行速度飞快，但是bitmap长度似乎有点问题

**7.11更新**

\#运行结果仍然是bitmap不存在，但至少能跑 1.本次更新修改了sd_is_socket逻辑，但是很奇怪我判断为来自网络直接返回才能跑起来，否则不能收到hook. 2.修改了一部分recvmsg读取的逻辑，有无问题仍在测试. 3.修改了send_to_afl的时间，应该是等进程那边执行完再发向afl，但是由于需要加入对当前种子有无读完的判断，send_to_afl和read_fron_afl的位置都有待斟酌。

**7.12更新**

1.sd_is_socket的问题来自于type和protocol参数设置问题，全都给0之后按预期运行，理论上排除了内部对recvmsg的引用外部可以全都hook。

2.发现如果不hook它本来也跑不起来，这是正常的吗？（输出是需要至少一个有效的种子

3.iov缓冲区和种子的长度不一致时应该这样处理

(a):种子长度小于总的iov长度，应该用完种子，返回一些空的iov

(b):种子长度大于总的iov长度，应该填满当前iov，并且完成一次返回，下一个全新的iov来接着读种子

~~基于上述想法send_to_afl()应该在每次种子读完，即feof(fp)时触发，并且read_from_afl()应保持同步~~

~~并且afl需要forkserver的执行情况，所以我们每次send_to_afl的时候forkserver必须处理完，所以它必须有hook的recvmsg的返回值~~

~~所以我把send_to_afl的操作直接放在下一次recvmsg触发的时候，这样理论上不需要usleep()。~~

**7.13更新**

1.注意到iovec *msg_iov中的iov_base的类型为void\*是一个未定类型的指针，所以无法直接用fread赋值，采用了buffer复制过去的方法.

2.加入了对剩余文件长度的判断

3.昨天考虑的第三点实现起来不太好，可能由于阻塞时间过长，afl会出一点问题（今天发现如果在一些地方加usleep afl也会报错）

所以还是采用了之前的usleep的方法

4.打印了一堆东西才知道是种子没有写。。。注释掉write_to_testcase中的retn程序可以运行（总算可以正常跑了

**TODO:attachPUT观察路径，寻找bitmap的长度问题**

**7.16更新**

~~1.加入timer控制效果不理想，速度仅为140/sec左右~~

~~2.dbg动调发现在dnsmasq的forward.c中receive_query line 1517~~

```c
  if ((n = recvmsg(listen->fd, &msg, 0)) == -1)
    return;

  if (n < (int)sizeof(struct dns_header) || 
      (msg.msg_flags & MSG_TRUNC) ||
      (header->hb3 & HB3_QR))
    return;
```

~~到了这里就直接返回，可我打印查看recvmsg的返回值确实有大于0的，但是基本上都在n<0那边retn了，不知道为啥~~

~~对于这个问题现在想的是hook部分肯定有问题，不然也不会出现那么多返回值为0的~~

~~观察了一下发现recvmsg的返回值不应该是0的，但是dnsmasq那边就是直接retn了，不知道咋回事~~

~~bitmap正确路径~~

~~receive_query-check_dns_listeners- 1844-1854-1857-2032-1838-1857-2032-1838-2041-check_dns_listeners~~

~~1265~~

~~hit twice~~ 

**7.24更新**

1.之前的理解有误，首先在

```c
  if ((n = recvmsg(listen->fd, &msg, 0)) == -1)
    return;
      if (n < (int)sizeof(struct dns_header) || 
      (msg.msg_flags & MSG_TRUNC) ||
      (header->hb3 & HB3_QR))
    return;
```

这里的退出时因为长度

后面在`indextoname`的退出为正常

2.之前的判断有误，第一次bitmap500+的原因是第一次包含了程序启动时的代码，而后面的不包括

3.修复了返回bytes为0的bug

**8.1更新**

历经千辛万苦，总算是调正确了dnsmasq的bitmap较短的问题

现在能跑到200+算是不小的进步了

之前原因是dnsmasq会检查recvmsg返回的msg_control的控制消息

而我们hook之后的recvmsg肯定是没有该消息的

于是我Handmade了一些IP数据塞到了控制消息里，使得它可以正常检验并通过

由于dns只check网络接口，所以只要塞一个网络接口过去就行，但是我一开始还想着把port也塞过去，他那边似乎无法解析

导致index也没读对，最后返回了no such device的问题

现在把port删掉，正常工作