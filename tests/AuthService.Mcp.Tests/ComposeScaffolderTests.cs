using AuthService.Mcp;
using Xunit;
using YamlDotNet.Serialization;

namespace AuthService.Mcp.Tests;

public class ComposeScaffolderTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("authservice-mcp-tests-").FullName;
    private readonly IDeserializer _deserializer = new DeserializerBuilder().Build();

    [Fact]
    public void AddService_CreatesComposeFile_WhenNoneExists()
    {
        var path = ComposeScaffolder.AddService(_tempDir, "v1.2.3", "PostgreSQL", "my-shop", "http://localhost:8080");

        Assert.True(File.Exists(path));
        var authservice = GetAuthServiceBlock(path);
        Assert.Equal("ghcr.io/konradcinkusz/authservice:v1.2.3", authservice["image"]);
    }

    [Fact]
    public void AddService_PreservesExistingServices_WhenComposeFileAlreadyExists()
    {
        var composePath = Path.Join(_tempDir, "docker-compose.yml");
        File.WriteAllText(composePath, "services:\n  web:\n    image: myapp:latest\n");

        ComposeScaffolder.AddService(_tempDir, "v1.2.3", "PostgreSQL", "my-shop", "http://localhost:8080");

        var root = _deserializer.Deserialize<Dictionary<object, object>>(File.ReadAllText(composePath));
        var services = Assert.IsType<Dictionary<object, object>>(root["services"]);
        Assert.True(services.ContainsKey("web"));
        Assert.True(services.ContainsKey("authservice"));
    }

    [Fact]
    public void AddService_Overwrites_WhenAuthServiceBlockAlreadyExists()
    {
        ComposeScaffolder.AddService(_tempDir, "v1.0.0", "PostgreSQL", "my-shop", "http://localhost:8080");

        var path = ComposeScaffolder.AddService(_tempDir, "v2.0.0", "SqlServer", "my-shop", "http://localhost:8080");

        var authservice = GetAuthServiceBlock(path);
        Assert.Equal("ghcr.io/konradcinkusz/authservice:v2.0.0", authservice["image"]);
    }

    [Fact]
    public void AddService_MountsTheSigningKeyAsASecret_WhereAuthServiceReadsIt()
    {
        var path = ComposeScaffolder.AddService(_tempDir, "v1.2.3", "PostgreSQL", "my-shop", "http://localhost:8080");

        var authservice = GetAuthServiceBlock(path);
        Assert.Equal(new List<object> { "authservice_signing_key" }, authservice["secrets"]);
        var environment = Assert.IsType<Dictionary<object, object>>(authservice["environment"]);
        Assert.Equal("/run/secrets/authservice_signing_key", environment["Jwt__PrivateKeyPath"]);

        var secrets = Assert.IsType<Dictionary<object, object>>(Root(path)["secrets"]);
        var secret = Assert.IsType<Dictionary<object, object>>(secrets["authservice_signing_key"]);
        Assert.Equal("./.authservice/signing-key.pem", secret["file"]);
    }

    [Fact]
    public void AddService_GivesTheProjectItsOwnIssuerAndAudience()
    {
        var path = ComposeScaffolder.AddService(_tempDir, "v1.2.3", "PostgreSQL", "my-shop", "http://localhost:8080");

        var environment = Assert.IsType<Dictionary<object, object>>(GetAuthServiceBlock(path)["environment"]);
        Assert.Equal("my-shop", environment["Jwt__Issuer"]);
        Assert.Equal("my-shop", environment["Jwt__Audience"]);
    }

    [Fact]
    public void AddService_PublishesTheKeySetAtTheAddressConsumersUse()
    {
        var path = ComposeScaffolder.AddService(_tempDir, "v1.2.3", "PostgreSQL", "my-shop", "https://auth.my-shop.example");

        var environment = Assert.IsType<Dictionary<object, object>>(GetAuthServiceBlock(path)["environment"]);
        Assert.Equal("https://auth.my-shop.example", environment["Jwt__PublicBaseUrl"]);
    }

    [Fact]
    public void AddService_PreservesExistingSecrets_WhenComposeFileAlreadyHasSome()
    {
        var composePath = Path.Join(_tempDir, "docker-compose.yml");
        File.WriteAllText(composePath, "secrets:\n  db_password:\n    file: ./db-password.txt\n");

        ComposeScaffolder.AddService(_tempDir, "v1.2.3", "PostgreSQL", "my-shop", "http://localhost:8080");

        var secrets = Assert.IsType<Dictionary<object, object>>(Root(composePath)["secrets"]);
        Assert.True(secrets.ContainsKey("db_password"));
        Assert.True(secrets.ContainsKey("authservice_signing_key"));
    }

    private Dictionary<object, object> Root(string composePath) =>
        _deserializer.Deserialize<Dictionary<object, object>>(File.ReadAllText(composePath));

    private Dictionary<object, object> GetAuthServiceBlock(string composePath)
    {
        var root = _deserializer.Deserialize<Dictionary<object, object>>(File.ReadAllText(composePath));
        var services = Assert.IsType<Dictionary<object, object>>(root["services"]);
        return Assert.IsType<Dictionary<object, object>>(services["authservice"]);
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);
}
