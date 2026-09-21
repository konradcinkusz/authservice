using YamlDotNet.Serialization;

namespace AuthService.Mcp.Tests;

public class ComposeScaffolderTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("authservice-mcp-tests-").FullName;
    private readonly IDeserializer _deserializer = new DeserializerBuilder().Build();

    [Fact]
    public void AddService_CreatesComposeFile_WhenNoneExists()
    {
        var path = ComposeScaffolder.AddService(_tempDir, "v1.2.3", "PostgreSQL");

        Assert.True(File.Exists(path));
        var authservice = GetAuthServiceBlock(path);
        Assert.Equal("ghcr.io/konradcinkusz/authservice:v1.2.3", authservice["image"]);
    }

    [Fact]
    public void AddService_PreservesExistingServices_WhenComposeFileAlreadyExists()
    {
        var composePath = Path.Combine(_tempDir, "docker-compose.yml");
        File.WriteAllText(composePath, "services:\n  web:\n    image: myapp:latest\n");

        ComposeScaffolder.AddService(_tempDir, "v1.2.3", "PostgreSQL");

        var root = _deserializer.Deserialize<Dictionary<object, object>>(File.ReadAllText(composePath));
        var services = Assert.IsType<Dictionary<object, object>>(root["services"]);
        Assert.True(services.ContainsKey("web"));
        Assert.True(services.ContainsKey("authservice"));
    }

    [Fact]
    public void AddService_Overwrites_WhenAuthServiceBlockAlreadyExists()
    {
        ComposeScaffolder.AddService(_tempDir, "v1.0.0", "PostgreSQL");

        var path = ComposeScaffolder.AddService(_tempDir, "v2.0.0", "SqlServer");

        var authservice = GetAuthServiceBlock(path);
        Assert.Equal("ghcr.io/konradcinkusz/authservice:v2.0.0", authservice["image"]);
    }

    private Dictionary<object, object> GetAuthServiceBlock(string composePath)
    {
        var root = _deserializer.Deserialize<Dictionary<object, object>>(File.ReadAllText(composePath));
        var services = Assert.IsType<Dictionary<object, object>>(root["services"]);
        return Assert.IsType<Dictionary<object, object>>(services["authservice"]);
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);
}
