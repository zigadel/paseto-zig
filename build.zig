const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- Static Library ---
    const lib = b.addStaticLibrary(.{
        .name = "paseto-zig",
        .root_module = lib_mod,
    });

    b.installArtifact(lib);

    // --- CLI Executable ---
    const exe = b.addExecutable(.{
        .name = "paseto-zig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Import the main library into the executable
    exe.root_module.addImport("paseto-zig_lib", lib_mod);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the CLI");
    run_step.dependOn(&run_cmd.step);

    // --- Tests ---
    const test_step = b.step("test", "Run all unit tests");

    const lib_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);

    const exe_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_tests.root_module.addImport("paseto-zig_lib", lib_mod);
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);

    const v2_tests = b.addTest(.{
        .root_source_file = b.path("src/cmds/v2.zig"),
        .target = target,
        .optimize = optimize,
    });
    v2_tests.root_module.addImport("paseto-zig_lib", lib_mod);
    test_step.dependOn(&b.addRunArtifact(v2_tests).step);

    // TODO dynamically walk the `/tests/` folder
    // const cli_tests = b.addTest(.{
    //     .root_source_file = b.path("tests/cli_test.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });
    // cli_tests.root_module.addImport("paseto-zig_lib", lib_mod);
    // test_step.dependOn(&b.addRunArtifact(cli_tests).step);

}
