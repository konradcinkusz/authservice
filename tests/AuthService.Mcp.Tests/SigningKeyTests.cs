using System.Security.Cryptography;
using AuthService.Mcp;
using Xunit;

namespace AuthService.Mcp.Tests;

public class SigningKeyTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("authservice-mcp-tests-").FullName;

    [Fact]
    public void GenerateRsaKeyPair_ProducesAPkcs8Key_OfTheSizeAuthServiceRequires()
    {
        var (privateKeyPem, _) = SigningKeyGenerator.GenerateRsaKeyPair();

        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", privateKeyPem);
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        Assert.Equal(2048, rsa.KeySize);
    }

    [Fact]
    public async Task WriteAsync_PutsTheKeyWhereTheComposeFileMountsItFrom()
    {
        var keyPath = await SigningKeyStore.WriteAsync(_tempDir, "pem");

        Assert.Equal(Path.Join(_tempDir, ".authservice", "signing-key.pem"), keyPath);
        Assert.Equal("pem", await File.ReadAllTextAsync(keyPath));
    }

    [Fact]
    public async Task WriteAsync_KeepsTheKeyOutOfGit()
    {
        await SigningKeyStore.WriteAsync(_tempDir, "pem");

        Assert.Equal("*\n", await File.ReadAllTextAsync(Path.Join(_tempDir, ".authservice", ".gitignore")));
    }

    [Fact]
    public async Task WriteAsync_LetsOnlyTheOwnerRead_EvenOverAnEarlierKey()
    {
        if (OperatingSystem.IsWindows())
            return;

        var earlier = Path.Join(_tempDir, ".authservice", "signing-key.pem");
        Directory.CreateDirectory(Path.GetDirectoryName(earlier)!);
        await File.WriteAllTextAsync(earlier, "old");
        File.SetUnixFileMode(earlier, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        var keyPath = await SigningKeyStore.WriteAsync(_tempDir, "new");

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(keyPath));
        Assert.Equal("new", await File.ReadAllTextAsync(keyPath));
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);
}
