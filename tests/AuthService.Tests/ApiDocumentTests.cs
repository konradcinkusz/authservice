using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Tests.Infrastructure;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The published API description. Every route is served both as /api/v1/... and as an unversioned
/// alias, and the document describes only the first, so a consumer reads one contract. Generating
/// it also fails at request time when two actions claim the same route, which nothing else notices.
/// </summary>
public class ApiDocumentTests : IntegrationTestBase
{
    protected override IReadOnlyDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        ["Swagger:Enabled"] = "true"
    };

    private async Task<JsonElement> DocumentAsync()
    {
        var response = await Factory.ClientFor().GetAsync("/swagger/v1/swagger.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    [Fact]
    public async Task The_document_describes_the_versioned_routes_and_none_of_the_aliases()
    {
        var document = await DocumentAsync();

        var paths = document.GetProperty("paths").EnumerateObject().Select(p => p.Name).ToList();
        Assert.NotEmpty(paths);
        Assert.All(paths, path => Assert.StartsWith("/api/v1/", path));
        // The controller's name is in the route as its class spells it; routing ignores the case.
        foreach (var expected in new[] { "/api/v1/auth/login", "/api/v1/organizations/{id}", "/api/v1/admin/users", "/api/v1/auth/2fa/login" })
            Assert.Contains(paths, path => string.Equals(path, expected, StringComparison.OrdinalIgnoreCase));
        Assert.Equal("Auth Service API", document.GetProperty("info").GetProperty("title").GetString());
    }

    [Fact]
    public async Task The_document_says_how_to_authenticate()
    {
        var document = await DocumentAsync();

        var bearer = document.GetProperty("components").GetProperty("securitySchemes").GetProperty("Bearer");
        Assert.Equal("http", bearer.GetProperty("type").GetString());
        Assert.Equal("Bearer", bearer.GetProperty("scheme").GetString());
        Assert.Equal("JWT", bearer.GetProperty("bearerFormat").GetString());
    }

    [Fact]
    public async Task The_interactive_page_is_served_when_the_document_is()
    {
        var response = await Factory.ClientFor().GetAsync("/swagger/index.html");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Auth Service API Documentation", await response.Content.ReadAsStringAsync());
    }
}
