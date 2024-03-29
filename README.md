# 🐈 pcat

pcat (process cat) is a simple tool for cat'ing the stdout and stderr of a process.

## Usage

There are two ways to use pcat (similarly to strace): pcat an exiting process (with PID), or pcat a new process (with a command).

```bash
pcat -p PID
pcat COMMAND [ARGS...]
```

## Example

### Monitor new process

```bash
pcat ping localhost
```

### Monitor existing process

```bash
# terminal 1
ping localhost > /dev/null
```

```bash
# terminal 2
sudo pcat -p $(ps -C "ping" -o pid= | head -1)
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

* Requires Linux kernel 5.3 or later, but let me know if you need support for older kernels. We just need to bring back the code removed in [commit/ceedab19](https://github.com/siadat/pcat/commit/ceedab194d6beddb7f01d3f6039261c3ec88db77?diff=split&w=1) for systems where PTRACE_SYSCALL_INFO_EXIT is not available.
* Tested with Zig version 0.12.0-dev.3496+a2df84d0f

