# pcat

pcat (process cat) is a simple tool for cat'ing the stdout and stderr of a process.

[![asciicast](https://asciinema.org/a/AnISVmtu2NVEs8ssFqQ8XVYEo.svg)](https://asciinema.org/a/AnISVmtu2NVEs8ssFqQ8XVYEo)

## Features

- Trace a child process
- Trace other processes by pid (requires root)
- Follow forked and cloned processes (WIP)

## Quick Start

```bash
zig build
```

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
