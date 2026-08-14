using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Tests.Infrastructure;
using Xunit;

namespace AuthService.Tests;

public class DataExportTests : IntegrationTestBase
{
    [Fact]
    public async Task Export_returns_the_users_profile_consents_and_session_metadata()
    {
        var (email, tokens) = await Client.RegisterAsync();
        Client.Authenticate(tokens);

        var response = await Client.GetAsync("/api/v1/auth/export");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        Assert.Equal(email, root.GetProperty("profile").GetProperty("email").GetString());

        // Registration records Terms and Privacy consent.
        Assert.Equal(2, root.GetProperty("consents").GetArrayLength());

        // One live session from registration.
        Assert.Equal(1, root.GetProperty("sessions").GetArrayLength());

        // A data export must not hand back working credentials.
        Assert.DoesNotContain(tokens.RefreshToken, json);
        Assert.DoesNotContain("passwordHash", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Export_requires_authentication()
    {
        var response = await Client.GetAsync("/api/v1/auth/export");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
