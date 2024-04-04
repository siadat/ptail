# ptail

ptail (process tail) is a simple tool for viewing the stdout and stderr of a process.
Think of it as tail -f for the output of a process.

When would it be useful?

1. There are situations in which the stdout and stderr of a process are captured and not shown. For example, `zig build test` captures stdout and stderr of processes and does not show them until the end of tests.
If tests are hanging (eg blocked) nothing is shown. You can use `ptail zig build test` to see the output of each test as it is running.

2. The process is running in the background and its stdout is either not written to disk, or you don't know where it is. For example, you can inspect what you language server (eg zls) is printing with the following command:
```
sudo ./zig-out/bin/pcat -p $(ps -C "zls" -o pid= | head -1)
```

## Usage

There are two ways to use ptail (similarly to strace): ptail an exiting process (with PID), or ptail a new process (with a command).

```bash
# new process
./zig-out/bin/ptail COMMAND [ARGS...]

# exiting process
sudo ./zig-out/bin/ptail -p PID
```

## Example

### Monitor new process

```bash
./zig-out/bin/ptail /usr/bin/bash -c 'ping localhost > /dev/null'
```

### Monitor existing process

```bash
# terminal 1
ping localhost > /dev/null
```

```bash
# terminal 2
sudo ./zig-out/bin/ptail -p $(ps -C "ping" -o pid= | head -1)
64 bytes from localhost (::1): icmp_seq=1 ttl=64 time=0.058 ms
64 bytes from localhost (::1): icmp_seq=2 ttl=64 time=0.067 ms
...
```

### Asciinema

[![asciicast](https://asciinema.org/a/AnISVmtu2NVEs8ssFqQ8XVYEo.svg)](https://asciinema.org/a/AnISVmtu2NVEs8ssFqQ8XVYEo)

## Build

```bash
zig build
```

* Requires Linux kernel 5.3 or later, but let me know if you need support for older kernels. We just need to bring back the code removed in [commit/ceedab19](https://github.com/siadat/ptail/commit/ceedab194d6beddb7f01d3f6039261c3ec88db77?diff=split&w=1) for systems where PTRACE_SYSCALL_INFO_EXIT is not available.
* Tested with Zig version 0.12.0-dev.3496+a2df84d0f

