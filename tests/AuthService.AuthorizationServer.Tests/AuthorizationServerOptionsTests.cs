using AuthService.Services;
using Xunit;

namespace AuthService.AuthorizationServer.Tests;

/// <summary>
/// What a deployment can get wrong in the authorization server's configuration, checked one
/// mistake at a time: each is refused with a message naming the setting, so it is a startup
/// failure and not a failed connection somewhere in Claude. <see cref="ClientRegistrationTests"/>
/// does the same through a booting host for the most common ones; this covers the rest directly.
/// </summary>
public class AuthorizationServerOptionsTests
{
    private const string Issuer = "https://auth.example.test";

    private static AuthorizationServerOptions Valid() => new()
    {
        EncryptionKey = Convert.ToBase64String(new byte[32]),
        Clients =
        [
            new AuthorizationServerClient
            {
                ClientId = "claude",
                DisplayName = "Claude",
                ClientSecret = new string('a', 64),
                RedirectUris = ["https://claude.ai/api/mcp/auth_callback"],
                AllowedScopes = ["notes:read", "offline_access"],
                AllowedResources = ["https://mcp.example.test/mcp"]
            }
        ]
    };

    private static IReadOnlyList<string> Errors(AuthorizationServerOptions options, string? apiIssuer = null, string? apiAudience = null) =>
        options.Validate(JwtSigningAlgorithm.RS256, Issuer, apiIssuer, apiAudience);

    public static TheoryData<string, Action<AuthorizationServerOptions>, string> Mistakes => new()
    {
        { "a retired key that is not a key", o => o.PreviousEncryptionKeys = ["not base64"], "AuthorizationServer:PreviousEncryptionKeys:0 must be the base64 encoding of 32 bytes." },
        { "a retired key of the wrong length", o => o.PreviousEncryptionKeys = [Convert.ToBase64String(new byte[16])], "PreviousEncryptionKeys:0" },
        { "a code that lives no time", o => o.AuthorizationCodeLifetimeSeconds = 0, "AuthorizationCodeLifetimeSeconds must be between 1 and 600." },
        { "a code that lives too long", o => o.AuthorizationCodeLifetimeSeconds = 601, "AuthorizationCodeLifetimeSeconds must be between 1 and 600." },
        { "an access token that lives no time", o => o.AccessTokenLifetimeMinutes = 0, "AccessTokenLifetimeMinutes must be between 1 and 60." },
        { "an access token that lives too long", o => o.AccessTokenLifetimeMinutes = 61, "AccessTokenLifetimeMinutes must be between 1 and 60." },
        { "a refresh token that lives no time", o => o.RefreshTokenLifetimeDays = 0, "RefreshTokenLifetimeDays must be between 1 and 365." },
        { "a refresh token that lives too long", o => o.RefreshTokenLifetimeDays = 366, "RefreshTokenLifetimeDays must be between 1 and 365." },
        { "a client with no id", o => o.Clients[0].ClientId = " ", "Clients:0:ClientId is required." },
        { "a client with no name for the consent step", o => o.Clients[0].DisplayName = "", "Clients:0:DisplayName is required" },
        { "a client with nowhere to send the user back to", o => o.Clients[0].RedirectUris = [], "Clients:0:RedirectUris needs at least one entry." },
        { "a scope with a space in it", o => o.Clients[0].AllowedScopes = ["notes read", "offline_access"], "which is not a valid scope token" },
        { "a scope with a quote in it", o => o.Clients[0].AllowedScopes = ["notes\"read", "offline_access"], "which is not a valid scope token" },
        { "a scope that is empty", o => o.Clients[0].AllowedScopes = ["", "offline_access"], "which is not a valid scope token" },
        { "openid, which this server does not implement", o => o.Clients[0].AllowedScopes = ["openid", "offline_access"], "contains openid" },
        { "a client with no resource to be issued tokens for", o => o.Clients[0].AllowedResources = [], "Clients:0:AllowedResources needs at least one entry" },
        { "a resource that is not https", o => o.Clients[0].AllowedResources = ["http://mcp.example.test/mcp"], "Clients:0:AllowedResources:0 must be an absolute https URI" },
        { "a token limit of nothing", o => o.Clients[0].TokenRequestsPerMinute = 0, "Clients:0:TokenRequestsPerMinute must be at least 1." },
        { "a per-user token limit of nothing", o => o.Clients[0].TokenRequestsPerUserPerMinute = 0, "Clients:0:TokenRequestsPerUserPerMinute must be at least 1." },
        { "a scope with no name", o => o.Scopes = [new AuthorizationServerScope { Name = "" }], "Scopes:0:Name is required." },
        { "a consumer page address with a query string", o => { o.Interaction.Mode = AuthorizationServerInteractionMode.External; o.Interaction.ExternalUrl = "https://app.example.test/connect?x=1"; }, "Interaction:ExternalUrl" },
    };

    [Theory]
    [MemberData(nameof(Mistakes))]
    public void A_mistake_is_refused_with_a_message_naming_the_setting(
        string mistake, Action<AuthorizationServerOptions> make, string expected)
    {
        var options = Valid();
        make(options);

        var errors = Errors(options);

        Assert.True(errors.Any(e => e.Contains(expected, StringComparison.Ordinal)), $"{mistake}: {string.Join(" | ", errors)}");
    }

    [Fact]
    public void A_client_id_used_twice_is_refused_at_the_second()
    {
        var options = Valid();
        var second = Valid().Clients[0];
        options.Clients.Add(second);

        var errors = Errors(options);

        Assert.Contains("AuthorizationServer:Clients:1:ClientId 'claude' is configured more than once.", errors);
    }

    [Fact]
    public void Every_mistake_is_reported_at_once_not_one_per_start()
    {
        var options = Valid();
        options.EncryptionKey = null;
        options.AccessTokenLifetimeMinutes = 0;
        options.Clients[0].RedirectUris = [];
        options.Clients[0].AllowedResources = [];

        var errors = Errors(options);

        Assert.Equal(4, errors.Count);
    }

    [Fact]
    public void A_deployment_with_no_client_has_no_authorization_server_to_get_wrong()
    {
        var options = new AuthorizationServerOptions { AccessTokenLifetimeMinutes = 0, EncryptionKey = "nonsense" };

        Assert.False(options.IsEnabled);
        Assert.Empty(Errors(options));
    }

    [Theory]
    [InlineData("https://auth.example.test", "https://mcp.example.test/mcp")]
    [InlineData("https://auth.example.test/", "https://mcp.example.test/mcp")]
    [InlineData("  https://auth.example.test/  ", "https://mcp.example.test/mcp")]
    public void An_api_issuer_and_audience_that_would_take_an_mcp_token_for_its_own_are_refused_however_the_issuer_is_written(
        string apiIssuer, string apiAudience)
    {
        var errors = Errors(Valid(), apiIssuer, apiAudience);

        Assert.Contains(errors, e => e.Contains("authservice's own API would accept MCP tokens"));
    }

    [Theory]
    [InlineData("https://auth.example.test", "AuthService")]
    [InlineData("AuthService", "https://mcp.example.test/mcp")]
    public void Either_the_issuer_or_the_audience_being_different_keeps_the_two_apart(string apiIssuer, string apiAudience)
    {
        Assert.Empty(Errors(Valid(), apiIssuer, apiAudience));
    }

    [Theory]
    [InlineData(32, true)]
    [InlineData(31, false)]
    [InlineData(33, false)]
    public void An_encryption_key_is_exactly_256_bits(int bytes, bool accepted)
    {
        Assert.Equal(accepted, AuthorizationServerOptions.TryDecodeKey(Convert.ToBase64String(new byte[bytes]), out var key));
        Assert.Equal(accepted, key.Length == 32);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not base64!")]
    public void Something_that_is_not_base64_is_not_a_key(string? value)
    {
        Assert.False(AuthorizationServerOptions.TryDecodeKey(value, out _));
    }

    [Fact]
    public void A_key_with_whitespace_around_it_is_still_the_key()
    {
        Assert.True(AuthorizationServerOptions.TryDecodeKey($"  {Convert.ToBase64String(new byte[32])}\n", out _));
    }

    [Fact]
    public void The_consent_step_describes_a_scope_in_the_deployments_words_then_its_own_and_then_the_scope_itself()
    {
        var options = Valid();
        options.Scopes = [new AuthorizationServerScope { Name = "notes:read", Description = "Read your notes" }];

        Assert.Equal("Read your notes", options.DescribeScope("notes:read"));
        Assert.Equal("Stay connected when you are not using it", options.DescribeScope("offline_access"));
        Assert.Equal("notes:write", options.DescribeScope("notes:write"));
    }

    [Fact]
    public void A_client_is_found_by_its_exact_id_and_no_other_spelling()
    {
        var options = Valid();

        Assert.Same(options.Clients[0], options.FindClient("claude"));
        Assert.Null(options.FindClient("Claude"));
        Assert.Null(options.FindClient(null));
    }
}
