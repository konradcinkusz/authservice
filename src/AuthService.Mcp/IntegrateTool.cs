using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;

namespace AuthService.Mcp;

// One tool, deliberately — this server exists to do the whole integration in a single call
// rather than exposing detect/scaffold/deploy as separate steps a client has to sequence.
[McpServerToolType]
public static class IntegrateTool
{
    [McpServerTool(
        Name = "integrate",
        Title = "Integrate authservice",
        ReadOnly = false,
        Idempotent = false,
        Destructive = true)]
    [Description(
        "Integrates authservice into the consumer project at targetPath, end to end: detects " +
        "the project's stack (ASP.NET Core, Node/Express, or Python/FastAPI) unless overridden, " +
        "adds an authservice service block to its docker-compose.yml, generates a JWT bearer " +
        "validation snippet for that stack, generates a fresh RS256 signing key that is never " +
        "reused across projects, and pins the latest published authservice release tag instead " +
        "of floating :latest. When deploy is true, also runs 'docker compose up -d'.")]
    public static async Task<string> Integrate(
        [Description("Absolute path to the consumer project's root directory.")]
        string targetPath,
        [Description("URL this authservice instance will be reachable at once deployed, e.g. " +
            "https://myapp-authservice.fly.dev. Defaults to http://localhost:8080 for local development.")]
        string authServiceUrl = "http://localhost:8080",
        [Description("Database provider for the authservice container: 'PostgreSQL' or 'SqlServer'.")]
        string databaseProvider = "PostgreSQL",
        [Description("Override stack detection: 'aspnetcore', 'node-express', or 'python-fastapi'. Leave unset to auto-detect.")]
        string? stack = null,
        [Description("Run 'docker compose up -d' after scaffolding. Defaults to false (scaffold only).")]
        bool deploy = false)
    {
        if (!Path.IsPathRooted(targetPath))
        {
            throw new ArgumentException($"targetPath '{targetPath}' must be absolute.", nameof(targetPath));
        }

        if (!Directory.Exists(targetPath))
        {
            throw new InvalidOperationException($"targetPath '{targetPath}' does not exist or is not a directory.");
        }

        var resolvedStack = stack is null ? StackDetector.Detect(targetPath) : ParseStack(stack);
        var summary = new StringBuilder();
        summary.AppendLine($"Stack: {resolvedStack}");

        var tag = await ReleasePinner.GetLatestTagAsync();
        summary.AppendLine(tag == "latest"
            ? "Image tag: latest — no published release found yet, pin a real tag once one exists"
            : $"Image tag: {tag} (pinned)");

        var (privateKeyPem, _) = SigningKeyGenerator.GenerateRsaKeyPair();
        var keyDir = Path.Join(targetPath, ".authservice");
        Directory.CreateDirectory(keyDir);
        var keyPath = Path.Join(keyDir, "signing-key.pem");
        await File.WriteAllTextAsync(keyPath, privateKeyPem);
        summary.AppendLine($"Signing key: {keyPath} — fresh RS256 key for this project only, never reuse it elsewhere");

        var composePath = ComposeScaffolder.AddService(targetPath, tag, databaseProvider);
        summary.AppendLine($"docker-compose.yml: {composePath} (authservice service added/updated)");

        var jwtConfigPath = JwtConfigGenerator.Generate(targetPath, resolvedStack, authServiceUrl);
        summary.AppendLine($"JWT validation config: {jwtConfigPath}");

        if (deploy)
        {
            summary.AppendLine("Deploy:");
            summary.AppendLine(await Deployer.RunComposeUpAsync(composePath));
        }
        else
        {
            summary.AppendLine(
                "Deploy: skipped (deploy=false). Review the generated files, then run " +
                "'docker compose up -d' yourself, or call integrate again with deploy=true.");
        }

        return summary.ToString();
    }

    private static ConsumerStack ParseStack(string stack) => stack.Trim().ToLowerInvariant() switch
    {
        "aspnetcore" or "asp.net" or "asp.net-core" => ConsumerStack.AspNetCore,
        "node-express" or "node" or "express" => ConsumerStack.NodeExpress,
        "python-fastapi" or "python" or "fastapi" => ConsumerStack.PythonFastApi,
        _ => throw new ArgumentException(
            $"Unknown stack '{stack}'. Use 'aspnetcore', 'node-express', or 'python-fastapi'.", nameof(stack)),
    };
}
