const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const exe = b.addExecutable(.{
        .name = "pcat",
        .root_source_file = .{ .path = "main.zig" },
        .target = target,
    });
    exe.linkLibC();

    const pid = b.option(u32, "pid", "pid of the process to cat");
    const exe_options = b.addOptions();
    exe.root_module.addOptions("build_options", exe_options);
    exe_options.addOption(?u32, "pid", pid);

    b.installArtifact(exe);

    // run:
    const run_exe = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the application");
    run_step.dependOn(&run_exe.step);
}
