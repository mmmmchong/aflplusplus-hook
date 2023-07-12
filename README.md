# aflplusplus-hook

### 目前的输出：

bitmap不存在

**7.11更新**

\#运行结果仍然是bitmap不存在，但至少能跑 1.本次更新修改了sd_is_socket逻辑，但是很奇怪我判断为来自网络直接返回才能跑起来，否则不能收到hook. 2.修改了一部分recvmsg读取的逻辑，有无问题仍在测试. 3.修改了send_to_afl的时间，应该是等进程那边执行完再发向afl，但是由于需要加入对当前种子有无读完的判断，send_to_afl和read_fron_afl的位置都有待斟酌。

**7.12更新**

1.sd_is_socket的问题来自于type和protocol参数设置问题，全都给0之后按预期运行，理论上排除了内部对recvmsg的引用外部可以全都hook。

2.发现如果不hook它本来也跑不起来，这是正常的吗？（输出是需要至少一个有效的种子

3.iov缓冲区和种子的长度不一致时应该这样处理

(a):种子长度小于总的iov长度，应该用完种子，返回一些空的iov

(b):种子长度大于总的iov长度，应该填满当前iov，并且完成一次返回，下一个全新的iov来接着读种子

基于上述想法send_to_afl()应该在每次种子读完，即feof(fp)时触发，并且read_from_afl()应保持同步

并且afl需要forkserver的执行情况，所以我们每次send_to_afl的时候forkserver必须处理完，所以它必须有hook的recvmsg的返回值

所以我把send_to_afl的操作直接放在下一次recvmsg触发的时候，这样理论上不需要usleep()。