using AuthService.Mcp;
using Xunit;

namespace AuthService.Mcp.Tests;

public class JwtConfigGeneratorTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("authservice-mcp-tests-").FullName;

    [Theory]
    [InlineData(ConsumerStack.AspNetCore)]
    [InlineData(ConsumerStack.NodeExpress)]
    [InlineData(ConsumerStack.PythonFastApi)]
    public void Generate_ValidatesTheProjectsIssuerAndAudience_ForEveryStack(ConsumerStack stack)
    {
        var content = File.ReadAllText(JwtConfigGenerator.Generate(_tempDir, stack, "https://auth.example", "my-shop"));

        Assert.DoesNotContain("__AUTHSERVICE", content);
        Assert.DoesNotContain("\"AuthService\"", content);
        Assert.Equal(2, CountOf(content, "\"my-shop\""));
        Assert.Contains("\"https://auth.example", content);
        Assert.DoesNotContain("auth.example//", content);
    }

    [Fact]
    public void Generate_AllowsPlainHttpMetadata_OnlyForAnHttpUrl()
    {
        var http = File.ReadAllText(JwtConfigGenerator.Generate(_tempDir, ConsumerStack.AspNetCore, "http://localhost:8080", "my-shop"));
        var https = File.ReadAllText(JwtConfigGenerator.Generate(_tempDir, ConsumerStack.AspNetCore, "https://auth.example", "my-shop"));

        Assert.Contains("options.RequireHttpsMetadata = false;", http);
        Assert.DoesNotContain("RequireHttpsMetadata", https);
    }

    [Fact]
    public void NormalizeUrl_DropsTheTrailingSlash()
    {
        Assert.Equal("https://auth.example", JwtConfigGenerator.NormalizeUrl("https://auth.example/"));
        Assert.Equal("http://localhost:8080", JwtConfigGenerator.NormalizeUrl("http://localhost:8080"));
    }

    [Theory]
    [InlineData("auth.example")]
    [InlineData("ftp://auth.example")]
    [InlineData("not a url")]
    public void NormalizeUrl_RejectsAnythingButAnAbsoluteHttpUrl(string url)
    {
        Assert.Throws<ArgumentException>(() => JwtConfigGenerator.NormalizeUrl(url));
    }

    private static int CountOf(string content, string value) =>
        (content.Length - content.Replace(value, "").Length) / value.Length;

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);
}
