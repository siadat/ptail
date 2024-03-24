const std = @import("std");
const c = @cImport({
    @cInclude("signal.h");
    @cInclude("sys/user.h");
    @cInclude("sys/ptrace.h");
});
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

const Logger = struct {
    const Self = @This();
    const stderr = std.io.getStdErr().writer();
    pid: std.os.pid_t,
    fn debug(self: Self, comptime format: []const u8, args: anytype) void {
        var bw = std.io.bufferedWriter(stderr);
        const writer = bw.writer();
        std.fmt.format(writer, "pid={} ", .{self.pid}) catch return;
        std.fmt.format(writer, format ++ "\n", args) catch return;
        bw.flush() catch return;
    }
};

pub fn runTracer(child_pid: std.os.pid_t) !void {
    _ = try waitpid(child_pid, 0);
    try std.os.ptrace(
        std.os.linux.PTRACE.SETOPTIONS,
        child_pid,
        0,
        c.PTRACE_O_TRACEVFORK | c.PTRACE_O_TRACEFORK | c.PTRACE_O_TRACECLONE | c.PTRACE_O_TRACESYSGOOD | c.PTRACE_O_TRACEEXEC | c.PTRACE_O_TRACEEXIT,
    );

    var writeSyscallEnter = true;
    const logger = Logger{ .pid = child_pid };
    while (true) {
        logger.debug("WHILE-BEGIN", .{});
        defer logger.debug("WHILE-END", .{});

        try std.os.ptrace(std.os.linux.PTRACE.SYSCALL, child_pid, 0, 0);
        const wait_result = try waitpid(child_pid, 0);
        logger.debug("wait_result: pid={} status={b}", .{ wait_result.pid, wait_result.status });

        if (std.os.linux.W.IFEXITED(wait_result.status)) {
            const exit_code = std.os.linux.W.EXITSTATUS(wait_result.status);
            logger.debug("exit code was {}", .{exit_code});
            break;
        }
        if (std.os.linux.W.IFSIGNALED(wait_result.status)) {
            logger.debug("signaled", .{});
            break;
        }

        const forked = wait_result.status >> 8 == (c.SIGTRAP | (c.PTRACE_EVENT_FORK << 8));
        const vforked = wait_result.status >> 8 == (c.SIGTRAP | (c.PTRACE_EVENT_VFORK << 8));
        const cloned = wait_result.status >> 8 == (c.SIGTRAP | (c.PTRACE_EVENT_CLONE << 8));
        if (forked or vforked or cloned) {
            var new_pid: usize = 0;
            try std.os.ptrace(
                std.os.linux.PTRACE.GETEVENTMSG,
                child_pid,
                0,
                @intFromPtr(&new_pid),
            );
            logger.debug("new_pid={}", .{new_pid});
            // NOTE: Experiment finding showed that wait_result.pid can be different from the original child_pid
            try runTracer(@intCast(new_pid));

            // TODO: we know this is a fork, vfork, or clone (and not a write
            // syscall), so we can skip the rest and continue
            // continue;
        }

        var regs: c.user_regs_struct = undefined;
        try std.os.ptrace(std.os.linux.PTRACE.GETREGS, child_pid, 0, @intFromPtr(&regs));
        var is_syscall = false;
        inline for (@typeInfo(std.os.linux.syscalls.X64).Enum.fields) |field| {
            if (field.value == regs.orig_rax) {
                logger.debug("looks like a syscall {s} ({})", .{ field.name, field.value });
                is_syscall = true;
                break;
            }
        }
        if (!is_syscall) {
            logger.debug("NOT a syscall, orig_rax = {}", .{regs.orig_rax});
            continue;
        }

        const syscall: std.os.linux.syscalls.X64 = @enumFromInt(regs.orig_rax); // TODO: switch on target architecture?
        switch (syscall) {
            .write => {
                logger.debug("write", .{});
                defer writeSyscallEnter = !writeSyscallEnter;
                if (!writeSyscallEnter) {
                    // we are exiting the syscall, however
                    // we have already done our work on syscall entry
                    continue;
                }

                if (regs.rdi != 1 and regs.rdi != 2) {
                    // not stdout or stderr
                    continue;
                }

                var word_buf: [@sizeOf(usize)]u8 = undefined;
                const word_count = 1 + (regs.rdx - 1) / @sizeOf(usize);
                var read_bytes: u64 = 0;
                for (0..word_count) |i| {
                    // read a word
                    // TODO: is there a way to do this with fewer syscalls?
                    try std.os.ptrace(
                        std.os.linux.PTRACE.PEEKDATA,
                        child_pid,
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
    try std.os.kill(std.os.linux.getpid(), std.os.linux.SIG.STOP);
    const err = std.os.execvpeZ(program, &argv, envp);

    std.log.err("execvpeZ error: {s}", .{@errorName(err)});
}

pub fn main() !void {
    // TODO: add `-v` to prefix lines with pid and fd
    var pid_arg: ?i32 = null;
    if (std.os.argv.len == 3) {
        if (std.mem.eql(u8, std.mem.sliceTo(std.os.argv[1], 0), "-p")) {
            pid_arg = try std.fmt.parseInt(i32, std.mem.sliceTo(std.os.argv[2], 0), 10);
        }
    }

    if (pid_arg) |pid| {
        // TODO: I cannot ctrl-c the process being traced after attaching to it, also nvim doesn't resize or exit properly
        try std.os.ptrace(std.os.linux.PTRACE.ATTACH, pid, 0, 0);
        runTracer(pid) catch |err| switch (err) {
            error.ProcessDoesNotExist => std.log.err("Process does not exist. Hint: if pid exists, you might need to run this command as root", .{}),
            else => unreachable,
        };
    } else {
        const child_pid = try std.os.fork();
        if (child_pid == 0) {
            try runChild(
                std.os.argv[1],
                std.os.argv[1..],
            );
        } else {
            try std.os.ptrace(std.os.linux.PTRACE.ATTACH, child_pid, 0, 0);
            try runTracer(child_pid);
        }
    }
}

test "test" {
    // TODO: add tests
    // Commands to test:
    //   date
    //   bash -c 'date > /dev/null'
    //   bash -c 'date > /dev/null & uname > /dev/null & wait"
}
