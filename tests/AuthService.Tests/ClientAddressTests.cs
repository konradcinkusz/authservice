using System.Net;
using System.Net.Http.Json;
using AuthService.Models;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Which address a request is attributed to. Rate limits and audit rows are keyed on it, so a
/// caller who can choose it can dodge the one and falsify the other.
/// </summary>
public class ClientIpTests
{
    private static DefaultHttpContext Request(string? remote, params (string Name, string Value)[] headers)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = remote is null ? null : IPAddress.Parse(remote);
        foreach (var (name, value) in headers)
            context.Request.Headers[name] = value;

        return context;
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Without_a_configured_header_the_connection_is_the_client_whatever_the_request_claims(string? configured)
    {
        var context = Request("203.0.113.9", ("X-Client-IP", "6.6.6.6"), ("X-Forwarded-For", "6.6.6.6"));

        Assert.Equal("203.0.113.9", context.ResolveClientIp(configured));
    }

    [Fact]
    public void A_configured_header_wins_over_the_connection()
    {
        var context = Request("10.0.0.2", ("X-Client-IP", "198.51.100.7"));

        Assert.Equal("198.51.100.7", context.ResolveClientIp("X-Client-IP"));
    }

    [Fact]
    public void The_first_entry_of_a_list_is_taken_and_trimmed()
    {
        var context = Request("10.0.0.2", ("X-Client-IP", "  198.51.100.7 , 10.0.0.1"));

        Assert.Equal("198.51.100.7", context.ResolveClientIp("X-Client-IP"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(",")]
    [InlineData(" , 198.51.100.7")]
    public void A_configured_header_that_is_blank_falls_back_to_the_connection(string value)
    {
        var context = Request("10.0.0.2", ("X-Client-IP", value));

        Assert.Equal("10.0.0.2", context.ResolveClientIp("X-Client-IP"));
    }

    [Fact]
    public void A_configured_header_the_request_does_not_carry_falls_back_to_the_connection()
    {
        Assert.Equal("10.0.0.2", Request("10.0.0.2").ResolveClientIp("X-Client-IP"));
    }

    [Fact]
    public void With_neither_header_nor_connection_the_client_is_unknown()
    {
        Assert.Equal("unknown", Request(remote: null).ResolveClientIp("X-Client-IP"));
    }
}

/// <summary>What an audit row records about the request it came from, when the deployment names its client-address header.</summary>
public class AuditRequestDetailsTests : IntegrationTestBase
{
    protected override IReadOnlyDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        ["Network:ClientIpHeader"] = "X-Real-Client-IP"
    };

    private async Task<AuditEvent> FailedLoginRowAsync(Action<HttpClient> configure)
    {
        var client = Factory.ClientFor();
        configure(client);

        await client.PostAsJsonAsync("/api/v1/auth/login", new { email = TestData.NewEmail("nobody"), password = "wrong" });

        return Assert.Single(await Factory.AuditAsync(AuditAction.LoginFailed));
    }

    [Fact]
    public async Task The_row_carries_the_client_address_from_the_configured_header_and_the_user_agent()
    {
        var row = await FailedLoginRowAsync(client =>
        {
            client.DefaultRequestHeaders.Add("X-Real-Client-IP", "198.51.100.7, 10.0.0.1");
            client.DefaultRequestHeaders.UserAgent.ParseAdd("audit-test/1.0");
        });

        Assert.Equal("198.51.100.7", row.IpAddress);
        Assert.Equal("audit-test/1.0", row.UserAgent);
    }

    [Fact]
    public async Task A_very_long_user_agent_is_cut_to_what_the_column_holds()
    {
        var row = await FailedLoginRowAsync(client =>
            client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", new string('x', 600)));

        Assert.Equal(512, row.UserAgent!.Length);
    }

}

/// <summary>
/// The default: no header is named, so a header the caller sends decides nothing. X-Forwarded-For
/// is the framework's forwarded-headers middleware's to judge, and it judges by the peer address,
/// which the in-memory test server does not have; it is left out here.
/// </summary>
public class AuditRequestSpoofingTests : IntegrationTestBase
{
    [Fact]
    public async Task A_caller_cannot_choose_the_address_an_audit_row_records()
    {
        var client = Factory.ClientFor();
        client.DefaultRequestHeaders.Add("X-Real-Client-IP", "6.6.6.6");

        await client.PostAsJsonAsync("/api/v1/auth/login", new { email = TestData.NewEmail("nobody"), password = "wrong" });

        var row = Assert.Single(await Factory.AuditAsync(AuditAction.LoginFailed));
        Assert.NotEqual("6.6.6.6", row.IpAddress);
    }
}
