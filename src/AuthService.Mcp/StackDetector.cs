using System.Text.Json;

namespace AuthService.Mcp;

public static class StackDetector
{
    public static ConsumerStack Detect(string targetPath)
    {
        if (Directory.EnumerateFiles(targetPath, "*.csproj", SearchOption.AllDirectories).Any())
        {
            return ConsumerStack.AspNetCore;
        }

        var packageJsonPath = Path.Join(targetPath, "package.json");
        if (File.Exists(packageJsonPath) && HasDependency(packageJsonPath, "express"))
        {
            return ConsumerStack.NodeExpress;
        }

        var requirementsPath = Path.Join(targetPath, "requirements.txt");
        if (File.Exists(requirementsPath) && ContainsFastApi(requirementsPath))
        {
            return ConsumerStack.PythonFastApi;
        }

        var pyprojectPath = Path.Join(targetPath, "pyproject.toml");
        if (File.Exists(pyprojectPath) && ContainsFastApi(pyprojectPath))
        {
            return ConsumerStack.PythonFastApi;
        }

        throw new InvalidOperationException(
            $"Could not detect a supported stack under '{targetPath}' (looked for a .csproj, " +
            "a package.json with an express dependency, or a requirements.txt/pyproject.toml " +
            "with a fastapi dependency). Pass the 'stack' parameter explicitly.");
    }

    private static bool HasDependency(string packageJsonPath, string dependencyName)
    {
        using var stream = File.OpenRead(packageJsonPath);
        using var document = JsonDocument.Parse(stream);
        var root = document.RootElement;

        foreach (var section in new[] { "dependencies", "devDependencies" })
        {
            if (root.TryGetProperty(section, out var deps) && deps.TryGetProperty(dependencyName, out _))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsFastApi(string path) =>
        File.ReadAllText(path).Contains("fastapi", StringComparison.OrdinalIgnoreCase);
}
