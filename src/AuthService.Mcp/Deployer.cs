using System.Diagnostics;

namespace AuthService.Mcp;

public static class Deployer
{
    public static async Task<string> RunComposeUpAsync(string composeFilePath)
    {
        var startInfo = new ProcessStartInfo("docker", $"compose -f \"{composeFilePath}\" up -d")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Failed to start the 'docker' process.");

        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        return process.ExitCode == 0
            ? $"docker compose up -d succeeded.\n{stdout}"
            : $"docker compose up -d failed (exit code {process.ExitCode}).\n{stderr}";
    }
}
