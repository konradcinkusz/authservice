using AuthService.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthService.Services;

/// <summary>
/// Copies the configured MCP clients into the authorization server's client store at startup.
///
/// Configuration is authoritative (A8), which is deliberately not SERVICE-API-PATTERNS.md §8's
/// "insert if missing, never overwrite": that rule protects edits an admin makes at runtime, and
/// v1 has no way to make any. A configured client is created or brought up to date, secret
/// included; a client that is no longer configured is deleted, together with its authorizations
/// and tokens, so a removed client's secret and refresh tokens stop working at the next start.
/// </summary>
public sealed class AuthorizationClientSync(
    IServiceScopeFactory scopeFactory,
    IOptionsMonitor<AuthorizationServerOptions> options,
    IMigrationCompletionSignal migrationSignal,
    ILogger<AuthorizationClientSync> logger
) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            // The client table arrives with the schema; see SERVICE-API-PATTERNS.md §7.
            await migrationSignal.WaitAsync(stoppingToken);
            await SyncAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            // Never take the host down: the rest of the service works without the authorization
            // server, and the next start retries. Connections fail with invalid_client meanwhile.
            logger.LogError(ex, "Registering the authorization server's clients failed; MCP clients cannot connect until it succeeds.");
        }
    }

    /// <summary>Brings the client store in line with configuration.</summary>
    public async Task SyncAsync(CancellationToken cancellationToken = default)
    {
        using var scope = scopeFactory.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var configured = options.CurrentValue.Clients;

        foreach (var client in configured)
        {
            var descriptor = Describe(client);
            var existing = await applications.FindByClientIdAsync(client.ClientId, cancellationToken);

            if (existing is null)
            {
                await applications.CreateAsync(descriptor, cancellationToken);
                logger.LogInformation("Registered MCP client {ClientId}", client.ClientId);
            }
            else
            {
                await applications.UpdateAsync(existing, descriptor, cancellationToken);
            }
        }

        var keep = configured.Select(c => c.ClientId).ToHashSet(StringComparer.Ordinal);
        var stale = new List<object>();

        await foreach (var application in applications.ListAsync(count: null, offset: null, cancellationToken))
        {
            var clientId = await applications.GetClientIdAsync(application, cancellationToken);
            if (clientId is null || !keep.Contains(clientId))
                stale.Add(application);
        }

        foreach (var application in stale)
        {
            var clientId = await applications.GetClientIdAsync(application, cancellationToken);

            // Deleting an application deletes its authorizations and tokens with it.
            await applications.DeleteAsync(application, cancellationToken);
            logger.LogWarning(
                "Removed MCP client {ClientId}, which is no longer configured, with its authorizations and tokens",
                clientId);
        }
    }

    private static OpenIddictApplicationDescriptor Describe(AuthorizationServerClient client)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
            ClientType = ClientTypes.Confidential,
            ApplicationType = ApplicationTypes.Web,
            ConsentType = ConsentTypes.Explicit,
            DisplayName = client.DisplayName,
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code
            },
            Requirements =
            {
                Requirements.Features.ProofKeyForCodeExchange
            }
        };

        foreach (var uri in client.RedirectUris)
            descriptor.RedirectUris.Add(new Uri(uri));

        foreach (var scope in client.AllowedScopes.Where(s => s != AuthorizationServerOptions.OfflineAccessScope))
            descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);

        // The library compares the permission string exactly, and Claude sends an origin-root
        // resource without its trailing slash, so both forms are allowed for one (N10).
        foreach (var resource in client.AllowedResources.SelectMany(ResourceForms))
            descriptor.Permissions.Add(Permissions.Prefixes.Resource + resource);

        return descriptor;
    }

    /// <summary>The forms of a resource URI a client may send for it.</summary>
    public static IEnumerable<string> ResourceForms(string resource)
    {
        var uri = new Uri(resource.Trim());
        if (uri.AbsolutePath == "/" && string.IsNullOrEmpty(uri.Query))
        {
            yield return uri.GetLeftPart(UriPartial.Authority);
            yield return uri.GetLeftPart(UriPartial.Authority) + "/";
        }
        else
        {
            yield return resource.Trim();
        }
    }
}
