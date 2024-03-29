# pcat

pcat (process cat) is a simple tool for cat'ing the stdout and stderr of a process.

[![asciicast](https://asciinema.org/a/AnISVmtu2NVEs8ssFqQ8XVYEo.svg)](https://asciinema.org/a/AnISVmtu2NVEs8ssFqQ8XVYEo)

## Features

- Trace a child process
- Trace other processes by pid (requires root)
- Follow forked and cloned processes

## Quick Start

```bash
zig build
```

* Requires Linux kernel 5.3 or later (2019), but let me know if you need support for older kernels. We just need to bring back the code removed in [commit/ceedab19](https://github.com/siadat/pcat/commit/ceedab194d6beddb7f01d3f6039261c3ec88db77?diff=split&w=1).
* Tested with Zig version 0.12.0-dev.3496+a2df84d0f

## Usage

```bash
./zig-out/bin/pcat -p PID
```

```bash
./zig-out/bin/pcat COMMAND [ARGS...]
```

## Example

### Monitor child process

```bash
./zig-out/bin/pcat ping localhost
```

### Monitor existing process

```bash
# terminal 1
ping localhost > /dev/null
```

```bash
# terminal 2
sudo ./zig-out/bin/pcat -p $(ps -C "ping" -o pid= | head -1)
64 bytes from localhost (::1): icmp_seq=1 ttl=64 time=0.058 ms
64 bytes from localhost (::1): icmp_seq=2 ttl=64 time=0.067 ms
...
```
