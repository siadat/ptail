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

    // test:
    const unit_tests = b.addTest(.{
        .optimize = .Debug,
        .root_source_file = .{ .path = "main.zig" },
        .error_tracing = true,
        .target = target,
    });
    unit_tests.linkLibC();
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
