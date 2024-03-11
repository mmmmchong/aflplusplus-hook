# A HIGH SPEED PROTOCOL FUZZ BASED ON SHM

A high speed protocol fuzz based on shared memory 

## Build

HSPFuzz is based on [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus), so to build HSPFuzz

```bash
git clone -b shm_fuzz https://github.com/mmmmchong/aflplusplus-hook.git

For aflplusplus

make

For shm_hook.so

gcc -shared -fPIC shm_hook.c -o shm_hook.so -lsystemd -ldl
```

# Seed

HSPFuzz uses the payload segment of the seed

`convert_pcap.py`  convert `.pcap`  in the current directory to `.raw`(which serves as the seed for fuzz)

```bash
python3 convert_pcap.py
```

## Usage

Similar to [desock (Preeny)](https://github.com/zardus/preeny) and [desockmulti](https://github.com/zyingp/desockmulti):

```bash
For tcp:

LD_PRELOAD=/path/to/HSPFuzz/shm_hook.so ./afl-fuzz -z -H 0:port -i testcase_dir -o findings_dir -- /path/to/program [...params...]

For udp:

LD_PRELOAD=/path/to/HSPFuzz/shm_hook.so ./afl-fuzz -z -H 1:port -i testcase_dir -o findings_dir -- /path/to/program [...params...]
```

`-z`  enable a checking mechanism may try to kill the process to improve performance when fuzz performance is poor.