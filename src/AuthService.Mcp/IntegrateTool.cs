using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
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
        "reused across projects and mounts it into the container as a compose secret, kept out " +
        "of git, gives the project its own token issuer and audience, and pins the latest " +
        "published authservice release tag instead of floating :latest. When deploy is true, " +
        "also runs 'docker compose up -d'.")]
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
        [Description("Issuer and audience of this project's tokens, set both in authservice and in the " +
            "generated validation code. Letters, digits and . _ : / - only. Defaults to the project " +
            "directory's name.")]
        string? issuer = null,
        [Description("Run 'docker compose up -d' after scaffolding. Defaults to false (scaffold only).")]
        bool deploy = false)
    {
        if (!Path.IsPathRooted(targetPath))
        {
            throw new McpException($"targetPath '{targetPath}' must be absolute.");
        }

        if (!Directory.Exists(targetPath))
        {
            throw new McpException($"targetPath '{targetPath}' does not exist or is not a directory.");
        }

        // Every input is checked before anything is written, so a bad value leaves no half-done
        // scaffold. McpException is the one exception whose message the SDK hands back to the
        // client; any other reaches it only as "An error occurred invoking 'integrate'".
        ConsumerStack resolvedStack;
        string resolvedIssuer;
        string publicBaseUrl;
        try
        {
            publicBaseUrl = JwtConfigGenerator.NormalizeUrl(authServiceUrl);
            resolvedIssuer = TokenIssuer.Resolve(issuer, targetPath);
            resolvedStack = stack is null ? StackDetector.Detect(targetPath) : ParseStack(stack);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            throw new McpException(ex.Message, ex);
        }

        var summary = new StringBuilder();
        summary.AppendLine($"Stack: {resolvedStack}");

        var tag = await ReleasePinner.GetLatestTagAsync();
        summary.AppendLine(tag == "latest"
            ? "Image tag: latest — no published release found yet, pin a real tag once one exists"
            : $"Image tag: {tag} (pinned)");

        var (privateKeyPem, _) = SigningKeyGenerator.GenerateRsaKeyPair();
        var keyPath = await SigningKeyStore.WriteAsync(targetPath, privateKeyPem);
        summary.AppendLine($"Signing key: {keyPath} — fresh RS256 key for this project only, never reuse it elsewhere. " +
            $"Mounted into the container as the compose secret '{ComposeScaffolder.SigningKeySecret}'; " +
            $"{SigningKeyStore.DirectoryName}/ is ignored by git.");

        summary.AppendLine($"Issuer and audience: {resolvedIssuer} (set in authservice and in the validation code)");

        var composePath = ComposeScaffolder.AddService(targetPath, tag, databaseProvider, resolvedIssuer, publicBaseUrl);
        summary.AppendLine($"docker-compose.yml: {composePath} (authservice service added/updated; " +
            "set ConnectionStrings__DefaultConnection to this project's own database before starting it)");

        var jwtConfigPath = JwtConfigGenerator.Generate(targetPath, resolvedStack, authServiceUrl, resolvedIssuer);
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
