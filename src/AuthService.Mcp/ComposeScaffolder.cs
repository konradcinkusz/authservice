using YamlDotNet.Serialization;

namespace AuthService.Mcp;

public static class ComposeScaffolder
{
    /// <summary>The compose secret the signing key is mounted as, at /run/secrets/&lt;name&gt;.</summary>
    public const string SigningKeySecret = "authservice_signing_key";

    // Each consuming project runs its own independent authservice instance (README.md,
    // "Deploying your own instance") — this merges a service block into whatever
    // docker-compose.yml the consumer already has rather than replacing the file.
    public static string AddService(string targetPath, string imageTag, string databaseProvider, string issuer, string publicBaseUrl)
    {
        var composePath = Path.Join(targetPath, "docker-compose.yml");

        var deserializer = new DeserializerBuilder().Build();
        var serializer = new SerializerBuilder().Build();

        var existingYaml = File.Exists(composePath) ? File.ReadAllText(composePath) : string.Empty;
        var root = string.IsNullOrWhiteSpace(existingYaml)
            ? new Dictionary<object, object>()
            : deserializer.Deserialize<Dictionary<object, object>>(existingYaml);

        Section(root, "services")["authservice"] = BuildServiceBlock(imageTag, databaseProvider, issuer, publicBaseUrl);

        // A file secret is bind-mounted read-only into the container, so the key never goes into
        // the image or into the environment that `docker inspect` lists.
        Section(root, "secrets")[SigningKeySecret] = new Dictionary<object, object>
        {
            ["file"] = "./" + SigningKeyStore.RelativePath,
        };

        File.WriteAllText(composePath, serializer.Serialize(root));
        return composePath;
    }

    private static Dictionary<object, object> Section(Dictionary<object, object> root, string name)
    {
        if (root.TryGetValue(name, out var existing) && existing is Dictionary<object, object> section)
            return section;

        var created = new Dictionary<object, object>();
        root[name] = created;
        return created;
    }

    private static Dictionary<object, object> BuildServiceBlock(string imageTag, string databaseProvider, string issuer, string publicBaseUrl) => new()
    {
        ["image"] = $"ghcr.io/konradcinkusz/authservice:{imageTag}",
        ["ports"] = new List<object>
        {
            "8080:8080",
        },
        ["secrets"] = new List<object>
        {
            SigningKeySecret,
        },
        ["environment"] = new Dictionary<object, object>
        {
            // The connection string stays a placeholder — README.md ("Deploying your own
            // instance") is explicit that it must be this project's own database, never one
            // copied between instances.
            ["ASPNETCORE_ENVIRONMENT"] = "Production",
            ["DatabaseProvider"] = databaseProvider,
            ["ConnectionStrings__DefaultConnection"] = "<set me — this project's own database>",
            ["Jwt__PrivateKeyPath"] = $"/run/secrets/{SigningKeySecret}",
            ["Jwt__Issuer"] = issuer,
            ["Jwt__Audience"] = issuer,
            // The address the generated validation code reaches authservice at, so the discovery
            // document links its key set there too.
            ["Jwt__PublicBaseUrl"] = publicBaseUrl,
        },
    };
}
