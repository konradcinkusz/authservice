namespace AuthService.Mcp;

public static class SigningKeyStore
{
    public const string DirectoryName = ".authservice";
    public const string FileName = "signing-key.pem";

    /// <summary>Where the key lives relative to the consumer project, and so to its docker-compose.yml.</summary>
    public const string RelativePath = DirectoryName + "/" + FileName;

    // The key is written where the generated compose file mounts it from. A .gitignore of "*"
    // in its directory ignores everything there, itself included, so the key stays out of the
    // repository without touching the project's own .gitignore.
    public static async Task<string> WriteAsync(string targetPath, string privateKeyPem)
    {
        var directory = Path.Join(targetPath, DirectoryName);
        Directory.CreateDirectory(directory);
        await File.WriteAllTextAsync(Path.Join(directory, ".gitignore"), "*\n");

        var keyPath = Path.Join(directory, FileName);
        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        await using (var stream = new FileStream(keyPath, options))
        await using (var writer = new StreamWriter(stream))
            await writer.WriteAsync(privateKeyPem);

        // UnixCreateMode applies only to a new file; this also narrows one left by an earlier run.
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        return keyPath;
    }
}
