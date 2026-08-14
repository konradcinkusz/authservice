using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using AuthService.Models;
using AuthService.DTOs;
using AuthService.Data;
using AuthService.Services;

namespace AuthService.Controllers;

/// <summary>
/// Admin-only endpoints for user and organization observation and management.
/// Requires the caller to be authenticated and hold the "Admin" or "SuperAdmin" role.
/// </summary>
[ApiController]
[EnableRateLimiting("api")]
[Route("api/v1/[controller]")]
[Route("api/[controller]")] // Unversioned alias. Prefer /api/v1.
[Authorize(Roles = "Admin,SuperAdmin")]
public class AdminController(
    UserManager<ApplicationUser> _userManager,
    ApplicationDbContext _context,
    ITokenService _tokenService,
    IAuditService _audit,
    ILogger<AdminController> _logger
) : ControllerBase
{
    private string? ActorId => User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
    private string? ActorEmail => User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;

    // ──────────────────────────────────────────────────────────────────────────
    // STATS
    // ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns platform-wide statistics for the admin dashboard overview.
    /// </summary>
    [HttpGet("stats")]
    [ProducesResponseType(typeof(AdminStatsDto), StatusCodes.Status200OK)]
    public async Task<ActionResult<AdminStatsDto>> GetStats()
    {
        var now = DateTime.UtcNow;
        var last7Days = now.AddDays(-7);
        var last30Days = now.AddDays(-30);

        var totalUsers = await _userManager.Users.CountAsync();
        var newLast7 = await _userManager.Users.CountAsync(u => u.CreatedAt >= last7Days);
        var newLast30 = await _userManager.Users.CountAsync(u => u.CreatedAt >= last30Days);
        var totalOrgs = await _context.Organizations.CountAsync();

        var stats = new AdminStatsDto(
            TotalUsers: totalUsers,
            NewUsersLast7Days: newLast7,
            NewUsersLast30Days: newLast30,
            TotalOrganizations: totalOrgs
        );

        return Ok(stats);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // USER LIST
    // ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns a paginated list of users, optionally filtered by a search term.
    /// </summary>
    /// <param name="page">1-based page number (default: 1)</param>
    /// <param name="pageSize">Results per page, max 100 (default: 20)</param>
    /// <param name="search">Optional search term (email or username prefix)</param>
    [HttpGet("users")]
    [ProducesResponseType(typeof(AdminUserListResponse), StatusCodes.Status200OK)]
    public async Task<ActionResult<AdminUserListResponse>> GetUsers(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? search = null)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var query = _userManager.Users.Where(u => !u.IsDeleted);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim().ToLower();
            query = query.Where(u =>
                (u.Email != null && u.Email.ToLower().Contains(term)) ||
                (u.UserName != null && u.UserName.ToLower().Contains(term)));
        }

        var totalCount = await query.CountAsync();
        var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);

        var users = await query
            .OrderByDescending(u => u.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        var userDtos = new List<AdminUserSummaryDto>(users.Count);

        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);
            userDtos.Add(new AdminUserSummaryDto(
                Id: user.Id,
                Email: user.Email!,
                UserName: user.UserName,
                ProfileImageUrl: user.ProfileImageUrl,
                CreatedAt: user.CreatedAt,
                LastLoginAt: user.LastLoginAt,
                Roles: roles.ToList()
            ));
        }

        return Ok(new AdminUserListResponse(
            Users: userDtos,
            TotalCount: totalCount,
            Page: page,
            PageSize: pageSize,
            TotalPages: totalPages
        ));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // USER DETAIL
    // ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns full details for a single user including organizations and roles.
    /// </summary>
    [HttpGet("users/{userId}")]
    [ProducesResponseType(typeof(AdminUserDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<AdminUserDetailDto>> GetUser(string userId)
    {
        var user = await _userManager.Users
            .Include(u => u.OrganizationMemberships)
            .ThenInclude(om => om.Organization)
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null)
            return NotFound(new { error = "User not found" });

        var roles = await _userManager.GetRolesAsync(user);

        var orgs = user.OrganizationMemberships
            .Select(om => new AdminOrgMembershipDto(
                OrgId: om.OrganizationId,
                OrgName: om.Organization.Name,
                OrgImageUrl: om.Organization.ImageUrl,
                Role: om.Role.ToString()))
            .ToList();

        var isLockedOut = await _userManager.IsLockedOutAsync(user);

        var detail = new AdminUserDetailDto(
            Id: user.Id,
            Email: user.Email!,
            UserName: user.UserName,
            ProfileImageUrl: user.ProfileImageUrl,
            CreatedAt: user.CreatedAt,
            LastLoginAt: user.LastLoginAt,
            Roles: roles.ToList(),
            IsLockedOut: isLockedOut,
            LockoutEnd: user.LockoutEnd,
            AccessFailedCount: user.AccessFailedCount,
            EmailConfirmed: user.EmailConfirmed,
            Organizations: orgs
        );

        return Ok(detail);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ROLE MANAGEMENT
    // ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Assigns a role to a user.
    /// </summary>
    [HttpPost("users/{userId}/roles")]
    [Authorize(Roles = "SuperAdmin")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AssignRole(string userId, [FromBody] AdminAssignRoleRequest request)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound(new { error = "User not found" });

        if (await _userManager.IsInRoleAsync(user, request.Role))
            return BadRequest(new { error = $"User already has role '{request.Role}'" });

        var result = await _userManager.AddToRoleAsync(user, request.Role);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        // Granting a role is the most consequential operation in the service and previously
        // left no trace at all — not even a log line.
        _logger.LogInformation("Admin {ActorId} assigned role {Role} to user {UserId}", ActorId, request.Role, userId);
        await _audit.LogAsync(AuditAction.AdminRoleAssigned, actorUserId: ActorId, actorEmail: ActorEmail,
            targetUserId: userId, metadata: new { role = request.Role });

        // A new role only reaches the token on the next refresh; revoking now makes the
        // change take effect on the next request instead of up to an access-token lifetime later.
        await _tokenService.RevokeRefreshTokensAsync(userId, RefreshTokenRevocationReason.AdminRevoked);

        return Ok(new { message = $"Role '{request.Role}' assigned to user {userId}" });
    }

    /// <summary>
    /// Removes a role from a user.
    /// </summary>
    [HttpDelete("users/{userId}/roles/{role}")]
    [Authorize(Roles = "SuperAdmin")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveRole(string userId, string role)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound(new { error = "User not found" });

        if (!await _userManager.IsInRoleAsync(user, role))
            return BadRequest(new { error = $"User does not have role '{role}'" });

        var result = await _userManager.RemoveFromRoleAsync(user, role);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        _logger.LogInformation("Admin {ActorId} removed role {Role} from user {UserId}", ActorId, role, userId);
        await _audit.LogAsync(AuditAction.AdminRoleRemoved, actorUserId: ActorId, actorEmail: ActorEmail,
            targetUserId: userId, metadata: new { role });

        // Revoking a role must not wait for the access token to expire.
        await _tokenService.RevokeRefreshTokensAsync(userId, RefreshTokenRevocationReason.AdminRevoked);

        return Ok(new { message = $"Role '{role}' removed from user {userId}" });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // LOCKOUT MANAGEMENT
    // ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Locks a user account and terminates its sessions.
    /// </summary>
    /// <remarks>
    /// The counterpart to unlock, which existed on its own: an admin who learned an account
    /// was compromised previously had no lever at all. Locking without revoking sessions
    /// would be theatre, so both happen here — refresh is now re-checked against lockout,
    /// so a locked account cannot roll its session forward.
    /// </remarks>
    [HttpPost("users/{userId}/lock")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> LockUser(string userId, [FromBody] AdminLockUserRequest? request = null)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound(new { error = "User not found" });

        if (userId == ActorId)
            return BadRequest(new { error = "You cannot lock your own account." });

        var until = request?.Until ?? DateTimeOffset.MaxValue;

        if (until <= DateTimeOffset.UtcNow)
            return BadRequest(new { error = "'until' must be in the future, or null for an indefinite lock." });

        // SetLockoutEndDateAsync is inert unless lockout is enabled for the user.
        if (!await _userManager.GetLockoutEnabledAsync(user))
            await _userManager.SetLockoutEnabledAsync(user, true);

        var result = await _userManager.SetLockoutEndDateAsync(user, until);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        await _tokenService.RevokeRefreshTokensAsync(userId, RefreshTokenRevocationReason.AdminLocked);

        _logger.LogInformation("Admin {ActorId} locked user {UserId} until {Until}", ActorId, userId, until);
        await _audit.LogAsync(AuditAction.AdminUserLocked, actorUserId: ActorId, actorEmail: ActorEmail,
            targetUserId: userId, metadata: new { until, indefinite = request?.Until == null });

        return Ok(new
        {
            message = request?.Until == null
                ? "User account locked indefinitely and all sessions revoked."
                : "User account locked and all sessions revoked.",
            lockoutEnd = until
        });
    }

    /// <summary>
    /// Unlocks a locked-out user account.
    /// </summary>
    [HttpPost("users/{userId}/unlock")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UnlockUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound(new { error = "User not found" });

        await _userManager.SetLockoutEndDateAsync(user, null);
        await _userManager.ResetAccessFailedCountAsync(user);

        _logger.LogInformation("Admin {ActorId} unlocked user {UserId}", ActorId, userId);
        await _audit.LogAsync(AuditAction.AdminUserUnlocked, actorUserId: ActorId, actorEmail: ActorEmail,
            targetUserId: userId);

        return Ok(new { message = "User account unlocked" });
    }

    /// <summary>
    /// Revokes every refresh token for a user, signing them out everywhere without locking
    /// the account.
    /// </summary>
    [HttpPost("users/{userId}/revoke-sessions")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RevokeSessions(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound(new { error = "User not found" });

        await _tokenService.RevokeRefreshTokensAsync(userId, RefreshTokenRevocationReason.AdminRevoked);

        _logger.LogInformation("Admin {ActorId} revoked all sessions for user {UserId}", ActorId, userId);
        await _audit.LogAsync(AuditAction.AdminUserSessionsRevoked, actorUserId: ActorId, actorEmail: ActorEmail,
            targetUserId: userId);

        return Ok(new
        {
            message = "All refresh tokens revoked. Existing access tokens remain valid until they expire."
        });
    }

    /// <summary>
    /// Soft-deletes a user account, scheduling permanent deletion after the retention period.
    /// </summary>
    /// <remarks>
    /// The admin surface could previously restore users it had no way to delete. This is the
    /// missing half; it mirrors the self-service delete in AuthController.
    /// </remarks>
    [HttpDelete("users/{userId}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> SoftDeleteUser(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound(new { error = "User not found" });

        if (userId == ActorId)
            return BadRequest(new { error = "You cannot delete your own account from the admin API." });

        if (user.IsDeleted)
            return BadRequest(new { error = "User is already deleted." });

        await _tokenService.RevokeRefreshTokensAsync(userId, RefreshTokenRevocationReason.AccountDeleted);

        user.IsDeleted = true;
        user.DeletedAt = DateTime.UtcNow;
        user.ScheduledPermanentDeletionAt = DateTime.UtcNow.AddDays(ApplicationUser.DefaultRetentionDays);

        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        _logger.LogInformation("Admin {ActorId} soft-deleted user {UserId}", ActorId, userId);
        await _audit.LogAsync(AuditAction.AdminUserSoftDeleted, actorUserId: ActorId, actorEmail: ActorEmail,
            targetUserId: userId,
            metadata: new { scheduledPermanentDeletionAt = user.ScheduledPermanentDeletionAt });

        return Ok(new
        {
            message = "User account soft-deleted.",
            scheduledPermanentDeletionAt = user.ScheduledPermanentDeletionAt,
            retentionDays = ApplicationUser.DefaultRetentionDays
        });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // SOFT-DELETED USERS
    // ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns users that have been soft-deleted (pending permanent deletion after retention period).
    /// </summary>
    [HttpGet("users/deleted")]
    [ProducesResponseType(typeof(DeletedUserListResponse), StatusCodes.Status200OK)]
    public async Task<ActionResult<DeletedUserListResponse>> GetDeletedUsers()
    {
        var deletedUsers = await _userManager.Users
            .Where(u => u.IsDeleted)
            .OrderByDescending(u => u.DeletedAt)
            .ToListAsync();

        var dtos = deletedUsers
            .Where(u => u.DeletedAt.HasValue && u.ScheduledPermanentDeletionAt.HasValue)
            .Select(u => new DeletedUserSummaryDto(
                Id: u.Id,
                Email: u.Email!,
                UserName: u.UserName,
                ProfileImageUrl: u.ProfileImageUrl,
                CreatedAt: u.CreatedAt,
                DeletedAt: u.DeletedAt!.Value,
                ScheduledPermanentDeletionAt: u.ScheduledPermanentDeletionAt!.Value
            ))
            .ToList();

        return Ok(new DeletedUserListResponse(Users: dtos, TotalCount: dtos.Count));
    }

    /// <summary>
    /// Restores a soft-deleted user account, cancelling the scheduled permanent deletion.
    /// </summary>
    [HttpPost("users/{userId}/restore")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> RestoreUser(string userId)
    {
        var user = await _userManager.Users
            .FirstOrDefaultAsync(u => u.Id == userId && u.IsDeleted);

        if (user == null)
            return NotFound(new { error = "Deleted user not found" });

        user.IsDeleted = false;
        user.DeletedAt = null;
        user.ScheduledPermanentDeletionAt = null;

        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        _logger.LogInformation("Admin {ActorId} restored soft-deleted user {UserId}", ActorId, userId);
        await _audit.LogAsync(AuditAction.AdminUserRestored, actorUserId: ActorId, actorEmail: ActorEmail,
            targetUserId: userId);

        return Ok(new { message = "User account restored successfully" });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // AUDIT LOG
    // ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Queries the security audit log.
    /// </summary>
    /// <remarks>
    /// Answers the questions that actually get asked after an incident — who granted this
    /// user SuperAdmin and when, which admin unlocked this account, show me every role change
    /// in the last 90 days — none of which unstructured log lines can answer.
    /// </remarks>
    /// <param name="action">Exact action name filter, e.g. <c>admin.role.assigned</c></param>
    /// <param name="actorUserId">Only events performed by this user</param>
    /// <param name="targetUserId">Only events performed on this user</param>
    /// <param name="organizationId">Only events scoped to this organization</param>
    /// <param name="from">Inclusive lower bound on OccurredAt (UTC)</param>
    /// <param name="to">Exclusive upper bound on OccurredAt (UTC)</param>
    /// <param name="page">1-based page number</param>
    /// <param name="pageSize">Results per page, max 200</param>
    [HttpGet("audit-events")]
    [ProducesResponseType(typeof(AuditEventListResponse), StatusCodes.Status200OK)]
    public async Task<ActionResult<AuditEventListResponse>> GetAuditEvents(
        [FromQuery] string? action = null,
        [FromQuery] string? actorUserId = null,
        [FromQuery] string? targetUserId = null,
        [FromQuery] string? organizationId = null,
        [FromQuery] DateTime? from = null,
        [FromQuery] DateTime? to = null,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 200);

        var query = _context.AuditEvents.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(action))
            query = query.Where(a => a.Action == action);

        if (!string.IsNullOrWhiteSpace(actorUserId))
            query = query.Where(a => a.ActorUserId == actorUserId);

        if (!string.IsNullOrWhiteSpace(targetUserId))
            query = query.Where(a => a.TargetUserId == targetUserId);

        if (!string.IsNullOrWhiteSpace(organizationId))
            query = query.Where(a => a.TargetOrganizationId == organizationId);

        if (from.HasValue)
            query = query.Where(a => a.OccurredAt >= from.Value);

        if (to.HasValue)
            query = query.Where(a => a.OccurredAt < to.Value);

        var totalCount = await query.CountAsync();

        var events = await query
            .OrderByDescending(a => a.OccurredAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new AuditEventDto(
                a.Id,
                a.OccurredAt,
                a.Action,
                a.ActorUserId,
                a.ActorEmail,
                a.TargetUserId,
                a.TargetOrganizationId,
                a.IpAddress,
                a.UserAgent,
                a.Succeeded,
                a.Metadata))
            .ToListAsync();

        return Ok(new AuditEventListResponse(
            Events: events,
            TotalCount: totalCount,
            Page: page,
            PageSize: pageSize,
            TotalPages: (int)Math.Ceiling(totalCount / (double)pageSize)));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ORGANIZATIONS
    // ──────────────────────────────────────────────────────────────────────────

    /// <summary>Returns a paginated list of all organizations.</summary>
    [HttpGet("organizations")]
    public async Task<IActionResult> GetOrganizations(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? search = null)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var query = _context.Organizations
            .AsNoTracking()
            .IgnoreQueryFilters() // include soft-deleted
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(o => o.Name.Contains(search));

        var total = await query.CountAsync();
        var items = await query
            .OrderByDescending(o => o.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(o => new
            {
                o.Id,
                o.Name,
                o.Description,
                o.ImageUrl,
                o.CreatedAt,
                o.CreatedByUserId,
                o.IsDeleted,
                o.DeletedAt,
                o.ScheduledPermanentDeletionAt,
                MemberCount = o.Members.Count,
            })
            .ToListAsync();

        return Ok(new
        {
            organizations = items,
            totalCount = total,
            page,
            pageSize,
            totalPages = (int)Math.Ceiling(total / (double)pageSize),
        });
    }

    /// <summary>Returns all invitations for an organization.</summary>
    [HttpGet("organizations/{organizationId}/invitations")]
    public async Task<IActionResult> GetOrganizationInvitations(string organizationId)
    {
        var items = await _context.OrganizationInvitations
            .AsNoTracking()
            .Where(i => i.OrganizationId == organizationId)
            .OrderByDescending(i => i.CreatedAt)
            .Select(i => new
            {
                i.Id,
                i.OrganizationId,
                i.Email,
                Role = i.Role.ToString(),
                i.InvitedByUserId,
                i.CreatedAt,
                i.ExpiresAt,
                i.IsAccepted,
                i.AcceptedAt,
                EmailStatus = i.EmailStatus.ToString(),
                i.LastEmailAttemptAt,
                i.EmailAttemptCount,
                i.LastEmailError,
            })
            .ToListAsync();

        return Ok(new { invitations = items, totalCount = items.Count });
    }
}
