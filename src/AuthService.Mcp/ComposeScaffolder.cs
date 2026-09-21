using YamlDotNet.Serialization;

namespace AuthService.Mcp;

public static class ComposeScaffolder
{
    // Each consuming project runs its own independent authservice instance (README.md,
    // "Deploying your own instance") — this merges a service block into whatever
    // docker-compose.yml the consumer already has rather than replacing the file.
    public static string AddService(string targetPath, string imageTag, string databaseProvider)
    {
        var composePath = Path.Combine(targetPath, "docker-compose.yml");

        var deserializer = new DeserializerBuilder().Build();
        var serializer = new SerializerBuilder().Build();

        var existingYaml = File.Exists(composePath) ? File.ReadAllText(composePath) : string.Empty;
        var root = string.IsNullOrWhiteSpace(existingYaml)
            ? new Dictionary<object, object>()
            : deserializer.Deserialize<Dictionary<object, object>>(existingYaml);

        if (root.TryGetValue("services", out var servicesObj) && servicesObj is Dictionary<object, object> existingServices)
        {
            existingServices["authservice"] = BuildServiceBlock(imageTag, databaseProvider);
        }
        else
        {
            root["services"] = new Dictionary<object, object>
            {
                ["authservice"] = BuildServiceBlock(imageTag, databaseProvider),
            };
        }

        File.WriteAllText(composePath, serializer.Serialize(root));
        return composePath;
    }

    private static Dictionary<object, object> BuildServiceBlock(string imageTag, string databaseProvider) => new()
    {
        ["image"] = $"ghcr.io/konradcinkusz/authservice:{imageTag}",
        ["ports"] = new List<object>
        {
            "8080:8080",
        },
        ["environment"] = new Dictionary<object, object>
        {
            // Placeholders — README.md ("Deploying your own instance") is explicit that the
            // connection string and Jwt:SecretKey must come from this project's own secrets,
            // never a value copied between instances.
            ["ASPNETCORE_ENVIRONMENT"] = "Production",
            ["DatabaseProvider"] = databaseProvider,
            ["ConnectionStrings__DefaultConnection"] = "<set me — this project's own database>",
            ["Jwt__Issuer"] = "AuthService",
            ["Jwt__Audience"] = "AuthService",
        },
    };
}
