using System.Security.Claims;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthService.Tests.Infrastructure;

/// <summary>
/// What a provider's sign-in leaves for the callback: who the provider says the user is.
/// The two optional claims are the ones the callback reads beyond the address.
/// </summary>
public sealed record ProviderIdentity(
    string Provider,
    string ProviderKey,
    string? Email,
    string? EmailVerified = null,
    string? Picture = null,
    string? AvatarUrl = null,
    string? AccessToken = null,
    string? ReturnUrl = null);

public static class TestExternalLogin
{
    public const string CallbackPath = "/api/v1/external-auth/callback";

    /// <summary>
    /// The cookie the provider's handler would have written when the user came back from the
    /// provider, protected with the application's own keys so the callback reads it as the real thing.
    /// </summary>
    public static string ExternalCookie(this AuthServiceFactory factory, ProviderIdentity identity)
    {
        List<Claim> claims = [new(ClaimTypes.NameIdentifier, identity.ProviderKey), new(ClaimTypes.Name, "Provider User")];

        void Add(string type, string? value)
        {
            if (value is not null)
                claims.Add(new Claim(type, value));
        }

        Add(ClaimTypes.Email, identity.Email);
        Add("email_verified", identity.EmailVerified);
        Add("picture", identity.Picture);
        Add("avatar_url", identity.AvatarUrl);

        var properties = new AuthenticationProperties();
        properties.Items["LoginProvider"] = identity.Provider;
        if (identity.ReturnUrl is not null)
            properties.Items["returnUrl"] = identity.ReturnUrl;
        if (identity.AccessToken is not null)
            properties.StoreTokens([new AuthenticationToken { Name = "access_token", Value = identity.AccessToken }]);

        var ticket = new AuthenticationTicket(
            new ClaimsPrincipal(new ClaimsIdentity(claims, identity.Provider)), properties, IdentityConstants.ExternalScheme);

        var options = factory.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(IdentityConstants.ExternalScheme);

        return $"{options.Cookie.Name}={options.TicketDataFormat.Protect(ticket)}";
    }

    /// <summary>The user's browser arriving at the callback with the provider's sign-in behind it.</summary>
    public static async Task<HttpResponseMessage> CallbackAsync(this AuthServiceFactory factory, ProviderIdentity? identity)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, CallbackPath);
        if (identity is not null)
            request.Headers.Add("Cookie", factory.ExternalCookie(identity));

        return await factory.ClientFor().SendAsync(request);
    }

    /// <summary>One query parameter of the redirect a response sent the browser to, or null.</summary>
    public static string? QueryValue(this HttpResponseMessage response, string name)
    {
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);

        return query.TryGetValue(name, out var value) ? value.ToString() : null;
    }
}
