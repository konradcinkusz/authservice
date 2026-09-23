using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AuthService.AuthorizationServer.Tests.Infrastructure;

/// <summary>Tokens as returned by the existing register/login/refresh endpoints.</summary>
public record ApiTokens(string AccessToken, string RefreshToken, int ExpiresIn, string TokenType = "Bearer");

/// <summary>Accounts, JSON Web Token decoding and the other small helpers every test class needs.</summary>
public static class TestAccounts
{
    /// <summary>Satisfies the configured Identity password policy (8+, upper, lower, digit, symbol).</summary>
    public const string Password = "Passw0rd!23";

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static string NewEmail(string prefix = "user") => $"{prefix}-{Guid.NewGuid():N}@example.test";

    /// <summary>Registers an account through the existing API and returns its tokens.</summary>
    public static async Task<(string Email, ApiTokens Tokens)> RegisterAsync(this HttpClient client, string? email = null)
    {
        email ??= NewEmail();

        var response = await client.PostAsJsonAsync("/api/v1/auth/register", new
        {
            email,
            password = Password,
            acceptedTermsVersion = AuthorizationServerFactory.TermsVersion,
            acceptedPrivacyVersion = AuthorizationServerFactory.PrivacyVersion
        });
        response.EnsureSuccessStatusCode();

        return (email, (await response.Content.ReadFromJsonAsync<ApiTokens>(Json))!);
    }

    public static async Task<ApiTokens> LoginAsync(this HttpClient client, string email)
    {
        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = Password });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<ApiTokens>(Json))!;
    }

    public static HttpRequestMessage WithBearer(this HttpRequestMessage request, string accessToken)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return request;
    }

    /// <summary>Decodes one segment of a compact JWS (0 = header, 1 = payload) without validating it.</summary>
    public static JsonDocument DecodeSegment(string jwt, int index)
    {
        var segments = jwt.Split('.');
        Assert.Equal(3, segments.Length);

        var segment = segments[index].Replace('-', '+').Replace('_', '/');
        segment = segment.PadRight(segment.Length + (4 - segment.Length % 4) % 4, '=');
        return JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(segment)));
    }

    public static string[] PropertyNames(this JsonElement element) =>
        element.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal).ToArray();

    public static string Sha256Base64Url(string value) =>
        Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(value)));

    public static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>A PKCE verifier and its S256 challenge.</summary>
public sealed record Pkce(string Verifier, string Challenge)
{
    public static Pkce Create()
    {
        var verifier = TestAccounts.Base64Url(RandomNumberGenerator.GetBytes(32));
        return new Pkce(verifier, TestAccounts.Sha256Base64Url(verifier));
    }
}

/// <summary>The token endpoint's successful response.</summary>
public sealed record TokenResult(string AccessToken, string? RefreshToken, int ExpiresIn, string TokenType, string? Scope);

/// <summary>
/// Plays both halves of an MCP connection against a test host: the browser (following the
/// authorization server's redirects and filling in its pages, with cookies) and the client
/// (calling the token endpoint server-to-server with its credentials), as Claude does.
/// </summary>
public sealed class AuthorizationFlowClient : IDisposable
{
    private readonly AuthorizationServerFactory _factory;

    public AuthorizationFlowClient(AuthorizationServerFactory factory)
    {
        _factory = factory;
        Browser = factory.CreateBrowserClient();
        Backchannel = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri(AuthorizationServerFactory.Issuer),
            HandleCookies = false
        });
    }

    /// <summary>A browser: keeps cookies, does not follow redirects.</summary>
    public HttpClient Browser { get; }

    /// <summary>The client's server-to-server channel: no cookies.</summary>
    public HttpClient Backchannel { get; }

    public static string AuthorizeUrl(
        Pkce pkce,
        string state,
        string? scope = AuthorizationServerFactory.Scope + " offline_access",
        string? resource = AuthorizationServerFactory.Resource,
        string redirectUri = AuthorizationServerFactory.RedirectUri,
        string clientId = AuthorizationServerFactory.ClientId,
        string? codeChallengeMethod = "S256",
        string? codeChallenge = null,
        IDictionary<string, string>? extra = null)
    {
        var parameters = new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["scope"] = scope,
            ["state"] = state,
            ["code_challenge"] = codeChallenge ?? pkce.Challenge,
            ["code_challenge_method"] = codeChallengeMethod,
            ["resource"] = resource
        };

        foreach (var (key, value) in extra ?? new Dictionary<string, string>())
            parameters[key] = value;

        return Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(
            "/connect/authorize",
            parameters.Where(p => p.Value is not null).Select(p => new KeyValuePair<string, string?>(p.Key, p.Value)));
    }

    /// <summary>
    /// Hosted mode, end to end in the browser: the authorization request, the sign-in page,
    /// the consent page, and back to the client. Returns where the browser was finally sent.
    /// </summary>
    public async Task<Uri> AuthorizeHostedAsync(string authorizeUrl, string email, string password = TestAccounts.Password, string consent = "accept")
    {
        var response = await Browser.GetAsync(authorizeUrl);

        if (IsLocalRedirect(response, "/connect/signin"))
        {
            response = await SignInAsync(response.Headers.Location!, email, password);
            Assert.True(IsLocalRedirect(response, "/connect/authorize"), await DescribeAsync(response));
            response = await Browser.GetAsync(response.Headers.Location);
        }

        if (IsLocalRedirect(response, "/connect/consent"))
            response = await ConsentAsync(response.Headers.Location!, consent);

        Assert.True(response.StatusCode == HttpStatusCode.Redirect || response.StatusCode == HttpStatusCode.Found,
            await DescribeAsync(response));
        return response.Headers.Location!;
    }

    /// <summary>Fills in and posts the sign-in page. Returns the response to the post.</summary>
    public async Task<HttpResponseMessage> SignInAsync(Uri signInPage, string email, string password)
    {
        var page = await Browser.GetAsync(signInPage);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);

        var form = HtmlForm.Parse(await page.Content.ReadAsStringAsync(), "signin-form");
        form["Email"] = email;
        form["Password"] = password;

        return await Browser.PostAsync(signInPage, new FormUrlEncodedContent(form));
    }

    /// <summary>Shows the consent page and posts the decision back to the authorization endpoint.</summary>
    public async Task<HttpResponseMessage> ConsentAsync(Uri consentPage, string decision)
    {
        var page = await Browser.GetAsync(consentPage);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);

        var form = HtmlForm.Parse(await page.Content.ReadAsStringAsync(), "consent-form");
        form["consent"] = decision;

        return await Browser.PostAsync("/connect/authorize", new FormUrlEncodedContent(form));
    }

    public Task<HttpResponseMessage> ExchangeCodeAsync(
        string code, string verifier, string? resource = AuthorizationServerFactory.Resource,
        string redirectUri = AuthorizationServerFactory.RedirectUri, string? secret = null, bool basic = true)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = verifier
        };
        if (resource is not null)
            form["resource"] = resource;

        return TokenAsync(form, secret, basic);
    }

    public Task<HttpResponseMessage> RefreshAsync(string refreshToken, string? resource = AuthorizationServerFactory.Resource, string? secret = null)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken
        };
        if (resource is not null)
            form["resource"] = resource;

        return TokenAsync(form, secret, basic: true);
    }

    /// <summary>
    /// A token request, authenticated with client_secret_basic, client_secret_post, or — with an
    /// empty secret — not at all.
    /// </summary>
    public Task<HttpResponseMessage> TokenAsync(IDictionary<string, string> form, string? secret = null, bool basic = true)
    {
        secret ??= _factory.ClientSecret;
        var body = new Dictionary<string, string>(form);
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token");

        if (secret.Length == 0)
        {
            body["client_id"] = AuthorizationServerFactory.ClientId;
        }
        else if (basic)
        {
            var credentials = $"{Uri.EscapeDataString(AuthorizationServerFactory.ClientId)}:{Uri.EscapeDataString(secret)}";
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));
        }
        else
        {
            body["client_id"] = AuthorizationServerFactory.ClientId;
            body["client_secret"] = secret;
        }

        request.Content = new FormUrlEncodedContent(body);
        return Backchannel.SendAsync(request);
    }

    public static async Task<TokenResult> ReadTokensAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode}: {body}");

        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;
        return new TokenResult(
            root.GetProperty("access_token").GetString()!,
            root.TryGetProperty("refresh_token", out var refresh) ? refresh.GetString() : null,
            root.GetProperty("expires_in").GetInt32(),
            root.GetProperty("token_type").GetString()!,
            root.TryGetProperty("scope", out var scope) ? scope.GetString() : null);
    }

    public static async Task<string> ReadErrorAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("error").GetString()!;
    }

    public static IDictionary<string, string> Query(Uri uri) =>
        Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query).ToDictionary(p => p.Key, p => p.Value.ToString());

    /// <summary>Hosted flow, code exchange and all, for tests that only need the tokens.</summary>
    public async Task<TokenResult> ConnectAsync(string email, string? scope = AuthorizationServerFactory.Scope + " offline_access")
    {
        var pkce = Pkce.Create();
        var redirect = await AuthorizeHostedAsync(AuthorizeUrl(pkce, "state-1", scope), email);
        var code = Query(redirect)["code"];
        return await ReadTokensAsync(await ExchangeCodeAsync(code, pkce.Verifier));
    }

    public static bool IsLocalRedirect(HttpResponseMessage response, string path) =>
        response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found &&
        response.Headers.Location is { } location &&
        (location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString.Split('?')[0])
            .Equals(path, StringComparison.OrdinalIgnoreCase);

    public static async Task<string> DescribeAsync(HttpResponseMessage response) =>
        $"{(int)response.StatusCode} {response.Headers.Location} {await response.Content.ReadAsStringAsync()}";

    public void Dispose()
    {
        Browser.Dispose();
        Backchannel.Dispose();
    }
}

/// <summary>The inputs of one form on a page, found by its data-testid.</summary>
public static class HtmlForm
{
    public static Dictionary<string, string> Parse(string html, string testId)
    {
        var start = html.IndexOf($"data-testid=\"{testId}\"", StringComparison.Ordinal);
        Assert.True(start >= 0, $"No form '{testId}' in the page:\n{html}");

        var end = html.IndexOf("</form>", start, StringComparison.Ordinal);
        var form = html[start..end];

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (System.Text.RegularExpressions.Match input in System.Text.RegularExpressions.Regex.Matches(form, "<input\\b[^>]*>"))
        {
            var name = Attribute(input.Value, "name");
            if (name is not null)
                fields[name] = Attribute(input.Value, "value") ?? string.Empty;
        }

        return fields;
    }

    private static string? Attribute(string tag, string name)
    {
        var match = System.Text.RegularExpressions.Regex.Match(tag, $"\\b{name}=\"([^\"]*)\"");
        return match.Success ? WebUtility.HtmlDecode(match.Groups[1].Value) : null;
    }
}

/// <summary>
/// A stand-in MCP server: validates bearer tokens exactly as <c>AP-MCP-01</c> is expected to —
/// through the authorization server's RFC 8414 metadata and the JWKS it names, with the issuer and
/// its own resource URI as the audience — and echoes what it saw.
/// </summary>
public sealed class TestResourceServer : IAsyncDisposable
{
    private readonly WebApplication _app;

    private TestResourceServer(WebApplication app)
    {
        _app = app;
        Client = app.GetTestClient();
    }

    public HttpClient Client { get; }

    public static async Task<TestResourceServer> StartAsync(AuthorizationServerFactory authorizationServer, string resource = AuthorizationServerFactory.Resource)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
        {
            options.MetadataAddress = AuthorizationServerFactory.Issuer + "/.well-known/oauth-authorization-server";
            options.BackchannelHttpHandler = authorizationServer.Server.CreateHandler();
            options.MapInboundClaims = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = AuthorizationServerFactory.Issuer,
                ValidAudience = resource,
                ClockSkew = TimeSpan.Zero
            };
        });
        builder.Services.AddAuthorization();

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/mcp", (ClaimsPrincipal user) => Results.Ok(new
        {
            sub = user.FindFirstValue("sub"),
            scope = user.FindFirstValue("scope"),
            clientId = user.FindFirstValue("client_id")
        })).RequireAuthorization();

        await app.StartAsync();
        return new TestResourceServer(app);
    }

    public Task<HttpResponseMessage> CallAsync(string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/mcp");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return Client.SendAsync(request);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync();
    }
}
