# aflplusplus-hook

### 目前的输出：

bitmap不存在

**7.11更新**

\#运行结果仍然是bitmap不存在，但至少能跑 1.本次更新修改了sd_is_socket逻辑，但是很奇怪我判断为来自网络直接返回才能跑起来，否则不能收到hook. 2.修改了一部分recvmsg读取的逻辑，有无问题仍在测试. 3.修改了send_to_afl的时间，应该是等进程那边执行完再发向afl，但是由于需要加入对当前种子有无读完的判断，send_to_afl和read_fron_afl的位置都有待斟酌。

**7.12更新**

1.sd_is_socket的问题来自于type和protocol参数设置问题，全都给0之后按预期运行，理论上排除了内部对recvmsg的引用外部可以全都hook。

