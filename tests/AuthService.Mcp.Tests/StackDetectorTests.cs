using AuthService.Mcp;
using Xunit;

namespace AuthService.Mcp.Tests;

public class StackDetectorTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("authservice-mcp-tests-").FullName;

    [Fact]
    public void Detect_ReturnsAspNetCore_WhenCsprojPresent()
    {
        File.WriteAllText(Path.Join(_tempDir, "Consumer.csproj"), "<Project Sdk=\"Microsoft.NET.Sdk\" />");

        var result = StackDetector.Detect(_tempDir);

        Assert.Equal(ConsumerStack.AspNetCore, result);
    }

    [Fact]
    public void Detect_ReturnsNodeExpress_WhenPackageJsonHasExpressDependency()
    {
        File.WriteAllText(
            Path.Join(_tempDir, "package.json"),
            "{ \"dependencies\": { \"express\": \"^4.19.0\" } }");

        var result = StackDetector.Detect(_tempDir);

        Assert.Equal(ConsumerStack.NodeExpress, result);
    }

    [Fact]
    public void Detect_IgnoresPackageJson_WhenExpressIsNotADependency()
    {
        File.WriteAllText(
            Path.Join(_tempDir, "package.json"),
            "{ \"dependencies\": { \"react\": \"^18.0.0\" } }");

        Assert.Throws<InvalidOperationException>(() => StackDetector.Detect(_tempDir));
    }

    [Fact]
    public void Detect_ReturnsPythonFastApi_WhenRequirementsTxtMentionsFastApi()
    {
        File.WriteAllText(Path.Join(_tempDir, "requirements.txt"), "fastapi==0.115.0\nuvicorn\n");

        var result = StackDetector.Detect(_tempDir);

        Assert.Equal(ConsumerStack.PythonFastApi, result);
    }

    [Fact]
    public void Detect_ReturnsPythonFastApi_WhenPyprojectTomlMentionsFastApi()
    {
        File.WriteAllText(Path.Join(_tempDir, "pyproject.toml"), "[project]\ndependencies = [\"fastapi\"]\n");

        var result = StackDetector.Detect(_tempDir);

        Assert.Equal(ConsumerStack.PythonFastApi, result);
    }

    [Fact]
    public void Detect_Throws_WhenNoKnownStackMarkerPresent()
    {
        Assert.Throws<InvalidOperationException>(() => StackDetector.Detect(_tempDir));
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);
}
