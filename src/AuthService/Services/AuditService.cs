using System.Text.Json;
using AuthService.Data;
using AuthService.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthService.Services;

/// <summary>
/// Records security-relevant actions to the <c>AuditEvents</c> table.
///
/// Writes are best-effort with respect to the caller: a failure to persist an audit row
/// is logged loudly but never turns a successful operation into a failed one. The one
/// exception is <see cref="EnqueueAsync"/>, which attaches the row to the caller's own
/// unit of work so that the action and its audit record commit together.
/// </summary>
public interface IAuditService
{
    /// <summary>Writes an audit row immediately (its own SaveChanges).</summary>
    Task LogAsync(
        string action,
        string? actorUserId = null,
        string? actorEmail = null,
        string? targetUserId = null,
        string? targetOrganizationId = null,
        bool succeeded = true,
        object? metadata = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds an audit row to the current DbContext without saving, so it is committed by the
    /// caller's next SaveChanges — use when the audited change and the record must be atomic.
    /// </summary>
    void Enqueue(
        string action,
        string? actorUserId = null,
        string? actorEmail = null,
        string? targetUserId = null,
        string? targetOrganizationId = null,
        bool succeeded = true,
        object? metadata = null);
}

public class AuditService(
    ApplicationDbContext _context,
    IHttpContextAccessor _httpContextAccessor,
    IOptions<NetworkOptions> _networkOptions,
    ILogger<AuditService> _logger
) : IAuditService
{
    private const int UserAgentMaxLength = 512;

    public async Task LogAsync(
        string action,
        string? actorUserId = null,
        string? actorEmail = null,
        string? targetUserId = null,
        string? targetOrganizationId = null,
        bool succeeded = true,
        object? metadata = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var entry = Build(action, actorUserId, actorEmail, targetUserId, targetOrganizationId, succeeded, metadata);
            _context.AuditEvents.Add(entry);
            await _context.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // An auth operation must not fail because auditing did. Surface it as an error so
            // a broken audit trail is visible in logs and alerting rather than silent.
            _logger.LogError(ex, "Failed to persist audit event {Action} (actor={ActorUserId}, target={TargetUserId})",
                action, actorUserId, targetUserId);
        }
    }

    public void Enqueue(
        string action,
        string? actorUserId = null,
        string? actorEmail = null,
        string? targetUserId = null,
        string? targetOrganizationId = null,
        bool succeeded = true,
        object? metadata = null)
    {
        try
        {
            _context.AuditEvents.Add(
                Build(action, actorUserId, actorEmail, targetUserId, targetOrganizationId, succeeded, metadata));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to enqueue audit event {Action}", action);
        }
    }

    private AuditEvent Build(
        string action,
        string? actorUserId,
        string? actorEmail,
        string? targetUserId,
        string? targetOrganizationId,
        bool succeeded,
        object? metadata)
    {
        var http = _httpContextAccessor.HttpContext;

        string? ip = null;
        string? userAgent = null;

        if (http != null)
        {
            ip = http.ResolveClientIp(_networkOptions.Value.ClientIpHeader);

            var ua = http.Request.Headers.UserAgent.ToString();
            if (!string.IsNullOrWhiteSpace(ua))
                userAgent = ua.Length > UserAgentMaxLength ? ua[..UserAgentMaxLength] : ua;
        }

        return new AuditEvent
        {
            Action = action,
            ActorUserId = actorUserId,
            ActorEmail = actorEmail,
            TargetUserId = targetUserId,
            TargetOrganizationId = targetOrganizationId,
            Succeeded = succeeded,
            IpAddress = ip,
            UserAgent = userAgent,
            Metadata = metadata is null ? null : JsonSerializer.Serialize(metadata)
        };
    }
}
