using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Extensions;

public static class CorsExtensions
{
    public const string FrontendPolicy = "Frontend";

    /// <summary>
    /// Registers a CORS policy driven entirely by configuration (<c>Cors:AllowedOrigins</c>).
    /// No provider-specific origins (cloud platforms, browser extensions, etc.) are hard-coded —
    /// add whatever your deployment needs to the configured origin list.
    /// </summary>
    public static IServiceCollection AddConfiguredCors(
        this IServiceCollection services,
        IConfiguration configuration,
        string policyName = FrontendPolicy)
    {
        var allowedOrigins = configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
            ?? Array.Empty<string>();

        services.AddCors(options =>
        {
            options.AddPolicy(policyName, policy =>
            {
                policy.WithOrigins(allowedOrigins)
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials();
            });
        });

        return services;
    }
}
