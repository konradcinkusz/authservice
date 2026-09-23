using AuthService.Extensions;
using AuthService.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace AuthService.Pages.Connect;

/// <summary>
/// The consent step, in Hosted mode: the client's display name, where the browser will be sent,
/// and what each requested scope means (AC2). The decision is posted back to the authorization
/// endpoint with the request's own parameters, so the library validates the whole request again
/// before a code is issued on the strength of it. What is shown comes from this server's
/// configuration, never from the request's own claims about itself.
/// </summary>
public class ConsentModel(
    SignInFlow _signInFlow,
    IOptionsSnapshot<AuthorizationServerOptions> _options
) : PageModel
{
    public string ClientName { get; private set; } = string.Empty;

    public string RedirectHost { get; private set; } = string.Empty;

    public string? UserEmail { get; private set; }

    public IReadOnlyList<(string Name, string Description)> Scopes { get; private set; } = [];

    /// <summary>The authorization request's parameters, posted back unchanged with the decision.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Parameters { get; private set; } = [];

    public async Task<IActionResult> OnGetAsync()
    {
        var options = _options.Value;
        if (options.Interaction.Mode != AuthorizationServerInteractionMode.Hosted)
            return NotFound();

        var request = $"{AuthorizationServerDefaults.AuthorizationEndpoint}{Request.QueryString}";

        var user = await _signInFlow.GetAuthorizationServerUserAsync(HttpContext);
        if (user is null)
            return LocalRedirect($"{AuthorizationServerDefaults.SignInPage}?returnUrl={Uri.EscapeDataString(request)}");

        var client = options.FindClient(Request.Query["client_id"]);
        var redirectUri = Request.Query["redirect_uri"].ToString();
        var scopes = Request.Query["scope"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // Checked here for what the page shows; the authorization endpoint checks it all again.
        if (client is null ||
            !client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal) ||
            scopes.Any(s => !client.AllowedScopes.Contains(s, StringComparer.Ordinal)))
        {
            return BadRequest("This consent request is not valid. Start again from the application.");
        }

        ClientName = client.DisplayName;
        RedirectHost = new Uri(redirectUri).Host;
        UserEmail = user.Email;
        Scopes = scopes.Select(s => (s, options.DescribeScope(s))).ToList();
        Parameters = Request.Query
            .SelectMany(p => p.Value.Select(v => new KeyValuePair<string, string>(p.Key, v ?? string.Empty)))
            .ToList();

        return Page();
    }
}
