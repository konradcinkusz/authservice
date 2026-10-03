namespace AuthService.Services;

/// <summary>Where this deployment's frontend lives, for the links in emails.</summary>
public static class FrontendUrl
{
    /// <summary>Right for local development, which is when nothing has been configured.</summary>
    public const string Default = "http://localhost:3000";

    /// <summary>
    /// <c>FrontendBaseUrl</c>, or <see cref="Default"/> when it is unset or blank, without a
    /// trailing slash. <c>appsettings.json</c> ships the setting as an empty string, which is set
    /// but blank: reading it with <c>??</c> kept the empty value and every emailed link came out
    /// relative, as <c>/reset-password?token=…</c>, which no mail client can follow.
    /// </summary>
    public static string BaseUrl(this IConfiguration configuration)
    {
        var configured = configuration["FrontendBaseUrl"];

        return (string.IsNullOrWhiteSpace(configured) ? Default : configured.Trim()).TrimEnd('/');
    }
}
