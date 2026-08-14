using System.Net;
using AuthService.Tests.Infrastructure;
using Xunit;

namespace AuthService.Tests;

public class HealthEndpointTests : IntegrationTestBase
{
    [Fact]
    public async Task Liveness_reports_healthy()
    {
        var response = await Client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Readiness_reports_healthy_once_the_schema_is_initialized()
    {
        var response = await Client.GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Healthy", body);
    }

    [Fact]
    public async Task Swagger_is_not_served_when_disabled_by_configuration()
    {
        var response = await Client.GetAsync("/swagger/v1/swagger.json");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
