using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Xunit;

namespace AuthService.Mcp.Tests;

/// <summary>Skipped where a shell script cannot stand in for the <c>docker</c> executable.</summary>
public sealed class FactOnUnixAttribute : FactAttribute
{
    public FactOnUnixAttribute()
    {
        if (OperatingSystem.IsWindows())
            Skip = "Needs a shell script on the PATH to stand in for docker.";
    }
}

/// <summary>
/// The server started the way an MCP client starts it, over stdio, once for the whole class. Nothing
/// it does reaches the network (its proxy is a closed port, so the release lookup fails at once and
/// the tag stays "latest") and nothing needs Docker (a script named docker answers for it).
/// </summary>
public sealed class IntegrateServerFixture : IAsyncLifetime
{
    public string Bin { get; } = Directory.CreateTempSubdirectory("authservice-mcp-bin-").FullName;
    public McpClient Client { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
        var path = Bin + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");

        Client = await McpClient.CreateAsync(new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "authservice-mcp-under-test",
            Command = host,
            Arguments = [Path.Join(AppContext.BaseDirectory, "AuthService.Mcp.dll")],
            EnvironmentVariables = new Dictionary<string, string?>
            {
                ["PATH"] = path,
                ["HTTPS_PROXY"] = "http://127.0.0.1:9",
                ["https_proxy"] = "http://127.0.0.1:9",
                ["ALL_PROXY"] = "http://127.0.0.1:9",
                ["NO_PROXY"] = "",
                ["no_proxy"] = ""
            }
        }));
    }

    public async Task DisposeAsync()
    {
        await Client.DisposeAsync();
        Directory.Delete(Bin, recursive: true);
    }
}

/// <summary>The tool as an MCP client meets it: the one tool the server offers, called by name.</summary>
public sealed class IntegrateToolServerTests(IntegrateServerFixture server) : IClassFixture<IntegrateServerFixture>, IDisposable
{
    private readonly string _project = Directory.CreateTempSubdirectory("authservice-mcp-e2e-").FullName;
    private McpClient Client => server.Client;

    public void Dispose() => Directory.Delete(_project, recursive: true);

    private async Task<(bool IsError, string Text)> CallAsync(Dictionary<string, object?> arguments)
    {
        var result = await Client.CallToolAsync("integrate", arguments);

        return (result.IsError == true, string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text)));
    }

    private Task<(bool IsError, string Text)> IntegrateAsync(params (string Name, object? Value)[] arguments)
    {
        var all = new Dictionary<string, object?> { ["targetPath"] = _project };
        foreach (var (name, value) in arguments)
            all[name] = value;

        return CallAsync(all);
    }

    private void WriteExpressProject() =>
        File.WriteAllText(Path.Join(_project, "package.json"), """{ "dependencies": { "express": "^4.0.0" } }""");

    private string Read(string relativePath) => File.ReadAllText(Path.Join(_project, relativePath));

    private void InstallFakeDocker(int exitCode, string stdout, string stderr)
    {
        var script = Path.Join(server.Bin, "docker");
        File.WriteAllText(script, $"#!/bin/sh\necho \"{stdout} $@\"\necho \"{stderr}\" >&2\nexit {exitCode}\n");

        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    // ─── What the server offers ──────────────────────────────────────────────

    [Fact]
    public async Task The_server_offers_one_tool_called_integrate_with_its_documented_inputs()
    {
        var tool = Assert.Single(await Client.ListToolsAsync());

        Assert.Equal("integrate", tool.Name);
        Assert.False(string.IsNullOrWhiteSpace(tool.Description));
        Assert.True(tool.ProtocolTool.Annotations?.DestructiveHint);
        Assert.False(tool.ProtocolTool.Annotations?.ReadOnlyHint);
        Assert.False(tool.ProtocolTool.Annotations?.IdempotentHint);

        var properties = tool.JsonSchema.GetProperty("properties");
        Assert.Equal(
            ["authServiceUrl", "databaseProvider", "deploy", "issuer", "stack", "targetPath"],
            properties.EnumerateObject().Select(p => p.Name).Order());
        Assert.All(properties.EnumerateObject(), p => Assert.True(p.Value.TryGetProperty("description", out _), p.Name));
        Assert.Equal(["targetPath"], tool.JsonSchema.GetProperty("required").EnumerateArray().Select(r => r.GetString()));
    }

    // ─── Integrating a project ───────────────────────────────────────────────

    [Fact]
    public async Task Integrating_a_project_writes_the_key_the_compose_service_and_the_validation_code()
    {
        WriteExpressProject();

        var (isError, text) = await IntegrateAsync();

        Assert.False(isError, text);
        Assert.Contains("Stack: NodeExpress", text);
        Assert.Contains("Image tag: latest", text);
        Assert.Contains("Deploy: skipped", text);

        var key = Read(Path.Join(".authservice", "signing-key.pem"));
        Assert.Contains("PRIVATE KEY", key);
        Assert.Equal("*\n", Read(Path.Join(".authservice", ".gitignore")));
        Assert.Contains("ghcr.io/konradcinkusz/authservice:latest", Read("docker-compose.yml"));
        var issuer = Path.GetFileName(_project);
        var validation = Read("authservice-auth.js");
        Assert.Contains("http://localhost:8080", validation);
        Assert.Contains(issuer, validation);
        Assert.Contains(issuer, Read("docker-compose.yml"));
    }

    [Fact]
    public async Task The_stack_the_address_the_issuer_and_the_database_can_all_be_chosen()
    {
        var (isError, text) = await IntegrateAsync(
            ("stack", "python"), ("authServiceUrl", "https://auth.example.test/"),
            ("issuer", "my-shop"), ("databaseProvider", "SqlServer"));

        Assert.False(isError, text);
        Assert.Contains("Stack: PythonFastApi", text);
        var validation = Read("authservice_auth.py");
        Assert.Contains("https://auth.example.test", validation);
        Assert.DoesNotContain("https://auth.example.test/\"", validation);
        Assert.Contains("my-shop", validation);
        var compose = Read("docker-compose.yml");
        Assert.Contains("SqlServer", compose);
        Assert.Contains("my-shop", compose);
    }

    [Fact]
    public async Task Integrating_again_updates_the_one_service_block_and_leaves_the_projects_own_services_alone()
    {
        WriteExpressProject();
        File.WriteAllText(Path.Join(_project, "docker-compose.yml"), "services:\n  web:\n    image: myapp:latest\n");

        await IntegrateAsync();
        await IntegrateAsync(("issuer", "second-run"));

        var compose = Read("docker-compose.yml");
        Assert.Contains("myapp:latest", compose);
        Assert.Equal(1, compose.Split('\n').Count(line => line.TrimEnd() == "  authservice:"));
        Assert.Contains("second-run", compose);
    }

    // ─── Inputs that are refused ─────────────────────────────────────────────

    [Fact]
    public async Task A_relative_path_is_refused_with_the_reason_and_nothing_is_written()
    {
        var (isError, text) = await CallAsync(new() { ["targetPath"] = "relative/dir" });

        Assert.True(isError);
        Assert.Contains("must be absolute", text);
    }

    [Fact]
    public async Task A_path_that_does_not_exist_is_refused_with_the_reason()
    {
        var (isError, text) = await CallAsync(new() { ["targetPath"] = Path.Join(_project, "missing") });

        Assert.True(isError);
        Assert.Contains("does not exist", text);
    }

    [Theory]
    [InlineData("stack", "cobol", "Unknown stack 'cobol'")]
    [InlineData("issuer", "not allowed!", "may contain only letters, digits")]
    [InlineData("authServiceUrl", "ftp://auth.example.test", "must be an absolute http or https URL")]
    [InlineData("authServiceUrl", "not a url", "must be an absolute http or https URL")]
    public async Task An_input_that_is_not_valid_is_refused_with_the_reason_before_anything_is_written(
        string name, string value, string expected)
    {
        WriteExpressProject();
        var before = Directory.GetFileSystemEntries(_project).Order().ToList();

        var (isError, text) = await IntegrateAsync((name, value));

        Assert.True(isError);
        Assert.Contains(expected, text);
        Assert.Equal(before, Directory.GetFileSystemEntries(_project).Order());
    }

    [Fact]
    public async Task A_project_whose_stack_cannot_be_told_is_refused_with_the_way_to_name_it()
    {
        var (isError, text) = await IntegrateAsync();

        Assert.True(isError);
        Assert.Contains("Could not detect a supported stack", text);
        Assert.Contains("'stack' parameter", text);
        Assert.Empty(Directory.GetFileSystemEntries(_project));
    }

    // ─── Deploying ───────────────────────────────────────────────────────────

    [FactOnUnix]
    public async Task Deploying_runs_compose_up_on_the_generated_file_and_reports_what_it_printed()
    {
        WriteExpressProject();
        InstallFakeDocker(exitCode: 0, stdout: "fake-docker", stderr: "");

        var (isError, text) = await IntegrateAsync(("deploy", true));

        Assert.False(isError, text);
        Assert.Contains("docker compose up -d succeeded.", text);
        Assert.Contains($"fake-docker compose -f {Path.Join(_project, "docker-compose.yml")} up -d", text);
        Assert.DoesNotContain("Deploy: skipped", text);
    }

    [FactOnUnix]
    public async Task A_deploy_that_fails_reports_the_exit_code_and_what_docker_said()
    {
        WriteExpressProject();
        InstallFakeDocker(exitCode: 3, stdout: "ignored", stderr: "no such service: postgres");

        var (isError, text) = await IntegrateAsync(("deploy", true));

        Assert.False(isError, text);
        Assert.Contains("docker compose up -d failed (exit code 3).", text);
        Assert.Contains("no such service: postgres", text);
        Assert.True(File.Exists(Path.Join(_project, "docker-compose.yml")));
    }
}
