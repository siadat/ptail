const std = @import("std");
const c = @cImport(@cInclude("sys/user.h"));
const builtin = @import("builtin");

const WaitError = error{
    ProcessDoesNotExist,
    InvalidFlags,
    Other,
};

// This is the same as std.os.waitpid, but it returns errors, instead of unreachable
pub fn waitpid(pid: std.os.pid_t, flags: u32) WaitError!std.os.WaitPidResult {
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        const rc = std.os.system.waitpid(pid, &status, @intCast(flags));
        switch (std.os.errno(rc)) {
            .SUCCESS => return std.os.WaitPidResult{
                .pid = @intCast(rc),
                .status = @bitCast(status),
            },
            .INTR => continue,
            .CHILD => return error.ProcessDoesNotExist, // The process specified does not exist. It would be a race condition to handle this error.
            .INVAL => return error.InvalidFlags, // Invalid flags.
            else => return error.Other,
        }
    }
}

pub fn runTracer(pid: std.os.pid_t) !void {
    var counter: u64 = 0;

    while (true) {
        const wait_result = try waitpid(pid, 0);
        if (std.os.linux.W.IFEXITED(wait_result.status)) {
            const exit_code = std.os.linux.W.EXITSTATUS(wait_result.status);
            std.log.info("exit code was {}", .{exit_code});
            break;
        }
        defer std.os.ptrace(std.os.linux.PTRACE.SYSCALL, pid, 0, 0) catch unreachable;

        var regs: c.user_regs_struct = undefined;
        try std.os.ptrace(std.os.linux.PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
        const syscall: std.os.linux.syscalls.X64 = @enumFromInt(regs.orig_rax); // TODO: switch on target architecture?
        switch (syscall) {
            .write => {
                if (regs.rdi != 1 and regs.rdi != 2) {
                    // not stdout or stderr
                    continue;
                }
                defer counter += 1;
                if (counter % 2 == 1) {
                    continue;
                }

                var word_buf: [@sizeOf(usize):0]u8 = undefined;
                const word_count = 1 + (regs.rdx - 1) / @sizeOf(usize);
                var read_bytes: u64 = 0;
                for (0..word_count) |i| {
                    // TODO: is there a way to do this with fewer syscalls?
                    // read a word
                    try std.os.ptrace(
                        std.os.linux.PTRACE.PEEKDATA,
                        pid,
                        regs.rsi + (i * @sizeOf(usize)),
                        @intFromPtr(&word_buf),
                    );
                    _ = try std.os.write(1, word_buf[0..@min(regs.rdx - read_bytes, @sizeOf(usize))]);
                    read_bytes = read_bytes + @sizeOf(usize); // this is wrong for the last word, but it is fine, because we will break out of the loop
                }
            },
            else => {},
        }
    }
}

fn runChild(program: [*:0]u8, argv_slice: [][*:0]const u8) !void {
    if (argv_slice.len > 1024) {
        std.log.err("Too many arguments", .{});
        return;
    }
    var argv: [1024:null]?[*:0]const u8 = undefined;
    for (argv_slice, 0..) |arg, i| {
        argv[i] = arg;
    }
    argv[argv_slice.len] = null;
    const envp: [*:null]?[*:0]const u8 = @ptrCast(std.os.environ.ptr);

    try std.os.ptrace(std.os.linux.PTRACE.TRACEME, 0, 0, 0);
    const err = std.os.execveZ(program, &argv, envp);

    std.log.err("execveZ error: {s}", .{@errorName(err)});
}

pub fn attachToProcess(pid: std.os.pid_t) !void {
    try std.os.ptrace(std.os.linux.PTRACE.ATTACH, pid, 0, 0);
}

pub fn main() !void {
    var pid_arg: ?i32 = null;
    if (std.os.argv.len == 3) {
        if (std.mem.eql(u8, std.mem.sliceTo(std.os.argv[1], 0), "-p")) {
            pid_arg = try std.fmt.parseInt(i32, std.mem.sliceTo(std.os.argv[2], 0), 10);
        }
    }

    if (pid_arg) |pid| {
        // TODO: I cannot ctrl-c the process being traced after attaching to it, also nvim doesn't resize or exit properly
        // TODO: follow subsequent forks
        try attachToProcess(pid);
        runTracer(pid) catch |err| switch (err) {
            error.ProcessDoesNotExist => std.log.err("Process does not exist. Hint: if pid exists, you might need to run this command as root", .{}),
            else => unreachable,
        };
    } else {
        const pid = try std.os.fork();
        if (pid == 0) {
            try runChild(
                std.os.argv[1],
                std.os.argv[1..],
            );
        } else {
            try runTracer(pid);
        }
    }
}

test "test" {
    // TODO
}
