using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AuthService.Models;
using AuthService.DTOs;
using AuthService.Data;
using AuthService.Services;

namespace AuthService.Controllers;

/// <summary>
/// Manages organization operations including creation, membership, and invitations
/// </summary>
[Authorize]
[ApiController]
[Route("api/[controller]")]
public class OrganizationsController(
    ApplicationDbContext _context,
    UserManager<ApplicationUser> _userManager,
    ILogger<OrganizationsController> _logger,
    InvitationService _invitationService
) : AuthControllerBase
{
    /// <summary>
    /// Gets all organizations the authenticated user is a member of.
    /// Includes soft-deleted organizations for owners so they can see deletion status and restore.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(typeof(List<OrganizationDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<List<OrganizationDto>>> GetUserOrganizations()
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var activeOrgs = await _context.OrganizationMemberships
            .Where(om => om.UserId == userId)
            .Include(om => om.Organization)
            .ThenInclude(o => o.Members)
            .OrderBy(om => om.JoinedAt)
            .Select(om => new OrganizationDto(
                om.Organization.Id,
                om.Organization.Name,
                om.Organization.Description,
                om.Organization.ImageUrl,
                om.Organization.CreatedAt,
                om.Organization.Members.Count,
                om.Role.ToString(),
                om.Organization.IsDeleted,
                om.Organization.ScheduledPermanentDeletionAt
            ))
            .ToListAsync();

        // Also get soft-deleted organizations where user is owner (bypassing global filter)
        var deletedOrgs = await _context.OrganizationMemberships
            .IgnoreQueryFilters()
            .Where(om => om.UserId == userId && om.Role == OrganizationRole.Owner && om.Organization.IsDeleted)
            .Include(om => om.Organization)
            .ThenInclude(o => o.Members)
            .Select(om => new OrganizationDto(
                om.Organization.Id,
                om.Organization.Name,
                om.Organization.Description,
                om.Organization.ImageUrl,
                om.Organization.CreatedAt,
                om.Organization.Members.Count,
                om.Role.ToString(),
                om.Organization.IsDeleted,
                om.Organization.ScheduledPermanentDeletionAt
            ))
            .ToListAsync();

        var allOrgs = activeOrgs
            .Concat(deletedOrgs)
            .DistinctBy(o => o.Id)
            .ToList();

        return Ok(allOrgs);
    }

    /// <summary>
    /// Gets detailed information about a specific organization
    /// </summary>
    [HttpGet("{id}")]
    [ProducesResponseType(typeof(OrganizationDetailDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<OrganizationDetailDto>> GetOrganization(string id)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var membership = await _context.OrganizationMemberships
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(om => om.OrganizationId == id && om.UserId == userId);

        if (membership == null)
            return NotFound(new { error = "Organization not found or access denied" });

        var organization = await _context.Organizations
            .IgnoreQueryFilters()
            .Include(o => o.Members)
                .ThenInclude(m => m.User)
            .FirstOrDefaultAsync(o => o.Id == id);

        if (organization == null)
            return NotFound();

        var members = organization.Members
            .Select(m => new OrganizationMemberDto(
                m.User.Id,
                m.User.Email!,
                m.User.UserName,
                m.User.ProfileImageUrl,
                m.Role.ToString(),
                m.JoinedAt
            ))
            .ToList();

        var response = new OrganizationDetailDto(
            organization.Id,
            organization.Name,
            organization.Description,
            organization.ImageUrl,
            organization.CreatedAt,
            members
        );

        return Ok(response);
    }

    /// <summary>
    /// Creates a new organization with the authenticated user as owner
    /// </summary>
    [HttpPost]
    [ProducesResponseType(typeof(OrganizationDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<OrganizationDto>> CreateOrganization([FromBody] CreateOrganizationRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var organization = new Organization
        {
            Name = request.Name,
            Description = request.Description,
            ImageUrl = request.ImageUrl,
            CreatedByUserId = userId
        };

        _context.Organizations.Add(organization);

        var membership = new OrganizationMembership
        {
            UserId = userId,
            OrganizationId = organization.Id,
            Role = OrganizationRole.Owner
        };

        _context.OrganizationMemberships.Add(membership);

        await _context.SaveChangesAsync();

        _logger.LogInformation("User {UserId} created organization {OrganizationId}", userId, organization.Id);

        var response = new OrganizationDto(
            organization.Id,
            organization.Name,
            organization.Description,
            organization.ImageUrl,
            organization.CreatedAt,
            1,
            OrganizationRole.Owner.ToString(),
            organization.IsDeleted,
            organization.ScheduledPermanentDeletionAt
        );

        return CreatedAtAction(nameof(GetOrganization), new { id = organization.Id }, response);
    }

    /// <summary>
    /// Updates an existing organization (requires Owner or Admin role)
    /// </summary>
    [HttpPut("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateOrganization(string id, [FromBody] CreateOrganizationRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var membership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == id && om.UserId == userId);

        if (membership == null || (membership.Role != OrganizationRole.Owner && membership.Role != OrganizationRole.Admin))
            return Forbid();

        var organization = await _context.Organizations.FindAsync(id);
        if (organization == null)
            return NotFound();

        organization.Name = request.Name;
        organization.Description = request.Description;
        organization.ImageUrl = request.ImageUrl;

        await _context.SaveChangesAsync();

        return Ok(new { message = "Organization updated successfully" });
    }

    /// <summary>
    /// Soft deletes an organization (requires Owner role).
    /// The organization will be disabled immediately and permanently deleted after the retention period (30 days).
    /// </summary>
    [HttpDelete("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteOrganization(string id)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var membership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == id && om.UserId == userId);

        if (membership == null || membership.Role != OrganizationRole.Owner)
            return Forbid();

        var organization = await _context.Organizations.FindAsync(id);
        if (organization == null)
            return NotFound();

        organization.IsDeleted = true;
        organization.DeletedAt = DateTime.UtcNow;
        organization.DeletedByUserId = userId;
        organization.ScheduledPermanentDeletionAt = DateTime.UtcNow.AddDays(Organization.DefaultRetentionDays);

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "User {UserId} soft-deleted organization {OrganizationId}. Scheduled for permanent deletion at {ScheduledDeletionAt}",
            userId, id, organization.ScheduledPermanentDeletionAt);

        return Ok(new
        {
            message = "Organization marked for deletion. It will be permanently deleted after the retention period.",
            scheduledPermanentDeletionAt = organization.ScheduledPermanentDeletionAt,
            retentionDays = Organization.DefaultRetentionDays
        });
    }

    /// <summary>
    /// Restores a soft-deleted organization (requires Owner role).
    /// Can only be done within the retention period before permanent deletion.
    /// </summary>
    [HttpPost("{id}/restore")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RestoreOrganization(string id)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var organization = await _context.Organizations
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(o => o.Id == id && o.IsDeleted);

        if (organization == null)
            return NotFound(new { error = "Organization not found or not deleted" });

        var membership = await _context.OrganizationMemberships
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(om => om.OrganizationId == id && om.UserId == userId);

        if (membership == null || membership.Role != OrganizationRole.Owner)
            return Forbid();

        organization.IsDeleted = false;
        organization.DeletedAt = null;
        organization.DeletedByUserId = null;
        organization.ScheduledPermanentDeletionAt = null;

        await _context.SaveChangesAsync();

        _logger.LogInformation("User {UserId} restored organization {OrganizationId}", userId, id);

        return Ok(new { message = "Organization restored successfully" });
    }

    /// <summary>
    /// Permanently and immediately deletes a soft-deleted organization (requires Owner role).
    /// This bypasses the retention period. This action cannot be undone.
    /// </summary>
    [HttpDelete("{id}/hard")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> HardDeleteOrganization(string id)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var organization = await _context.Organizations
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(o => o.Id == id && o.IsDeleted);

        if (organization == null)
            return NotFound(new { error = "Organization not found or not pending deletion" });

        var membership = await _context.OrganizationMemberships
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(om => om.OrganizationId == id && om.UserId == userId);

        if (membership == null || membership.Role != OrganizationRole.Owner)
            return Forbid();

        _context.Organizations.Remove(organization);
        await _context.SaveChangesAsync();

        _logger.LogInformation("User {UserId} hard-deleted organization {OrganizationId}", userId, id);

        return Ok(new { message = "Organization permanently deleted" });
    }

    /// <summary>
    /// Invites a user to join the organization via email (requires Owner or Admin role)
    /// </summary>
    [HttpPost("{id}/invite")]
    [ProducesResponseType(typeof(InvitationDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<InvitationDto>> InviteMember(string id, [FromBody] InviteMemberRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var membership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == id && om.UserId == userId);

        if (membership == null || (membership.Role != OrganizationRole.Owner && membership.Role != OrganizationRole.Admin))
            return Forbid();

        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser != null)
        {
            var existingMembership = await _context.OrganizationMemberships
                .AnyAsync(om => om.OrganizationId == id && om.UserId == existingUser.Id);

            if (existingMembership)
                return BadRequest(new { error = "User is already a member of this organization" });
        }

        var pendingInvitation = await _context.OrganizationInvitations
            .FirstOrDefaultAsync(oi => oi.OrganizationId == id && oi.Email == request.Email && !oi.IsAccepted && oi.ExpiresAt > DateTime.UtcNow);

        if (pendingInvitation != null)
            return BadRequest(new { error = "An invitation has already been sent to this email" });

        if (!Enum.TryParse<OrganizationRole>(request.Role, true, out var role))
            return BadRequest(new { error = "Invalid role" });

        var invitation = new OrganizationInvitation
        {
            OrganizationId = id,
            Email = request.Email,
            Role = role,
            InvitedByUserId = userId
        };

        _context.OrganizationInvitations.Add(invitation);
        await _context.SaveChangesAsync();

        _logger.LogInformation("User {UserId} invited {Email} to organization {OrganizationId}", userId, request.Email, id);

        var organization = await _context.Organizations.FindAsync(id);
        var inviter = await _userManager.FindByIdAsync(userId);

        var (success, errorMessage) = await _invitationService.SendInvitationEmailAsync(
            invitation,
            organization!.Name,
            inviter?.UserName ?? inviter?.Email
        );

        if (!success)
        {
            _logger.LogWarning(
                "Invitation created for {Email} but email sending failed: {ErrorMessage}. Retry is scheduled.",
                request.Email, errorMessage);
        }

        var response = new InvitationDto(
            invitation.Id,
            invitation.OrganizationId,
            organization!.Name,
            invitation.Email,
            invitation.Role.ToString(),
            invitation.CreatedAt,
            invitation.ExpiresAt,
            invitation.IsAccepted,
            invitation.EmailStatus.ToString(),
            invitation.EmailAttemptCount,
            invitation.LastEmailAttemptAt,
            invitation.NextRetryAt,
            invitation.LastEmailError
        );

        return Ok(response);
    }

    /// <summary>
    /// Accepts an organization invitation using the invitation token
    /// </summary>
    [HttpPost("invitations/accept")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AcceptInvitation([FromBody] AcceptInvitationRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound();

        var invitation = await _context.OrganizationInvitations
            .Include(oi => oi.Organization)
            .FirstOrDefaultAsync(oi => oi.Token == request.Token && oi.Email == user.Email);

        if (invitation == null)
            return NotFound(new { error = "Invitation not found" });

        if (invitation.IsAccepted)
            return BadRequest(new { error = "Invitation has already been accepted" });

        if (invitation.ExpiresAt < DateTime.UtcNow)
            return BadRequest(new { error = "Invitation has expired" });

        var existingMembership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == invitation.OrganizationId && om.UserId == userId);

        if (existingMembership != null)
        {
            if (!invitation.IsAccepted)
            {
                invitation.IsAccepted = true;
                invitation.AcceptedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();
            }

            _logger.LogInformation("User {UserId} tried to accept invitation but is already a member of organization {OrganizationId}", userId, invitation.OrganizationId);
            return Ok(new { message = "Invitation accepted successfully", organizationId = invitation.OrganizationId });
        }

        var membership = new OrganizationMembership
        {
            UserId = userId,
            OrganizationId = invitation.OrganizationId,
            Role = invitation.Role
        };

        _context.OrganizationMemberships.Add(membership);

        invitation.IsAccepted = true;
        invitation.AcceptedAt = DateTime.UtcNow;

        try
        {
            await _context.SaveChangesAsync();
        }
        catch (DbUpdateException)
        {
            // Could be a duplicate-membership race from a concurrent accept request.
            var membershipCheck = await _context.OrganizationMemberships
                .AnyAsync(om => om.OrganizationId == invitation.OrganizationId && om.UserId == userId);

            if (!membershipCheck)
                throw;

            // Membership was created by a concurrent request — ensure the invitation is marked accepted.
            invitation.IsAccepted = true;
            invitation.AcceptedAt = DateTime.UtcNow;
            _context.Entry(invitation).State = EntityState.Modified;
            await _context.SaveChangesAsync();

            _logger.LogInformation("User {UserId} accepted invitation to organization {OrganizationId} (concurrent request handled)", userId, invitation.OrganizationId);
            return Ok(new { message = "Invitation accepted successfully", organizationId = invitation.OrganizationId });
        }

        _logger.LogInformation("User {UserId} accepted invitation to organization {OrganizationId}", userId, invitation.OrganizationId);

        return Ok(new { message = "Invitation accepted successfully", organizationId = invitation.OrganizationId });
    }

    /// <summary>
    /// Gets all pending invitations for the authenticated user
    /// </summary>
    [HttpGet("invitations")]
    [ProducesResponseType(typeof(List<InvitationDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<List<InvitationDto>>> GetPendingInvitations()
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound();

        var invitations = await _context.OrganizationInvitations
            .Include(oi => oi.Organization)
            .Where(oi => oi.Email == user.Email && !oi.IsAccepted && oi.ExpiresAt > DateTime.UtcNow)
            .Select(oi => new InvitationDto(
                oi.Id,
                oi.OrganizationId,
                oi.Organization.Name,
                oi.Email,
                oi.Role.ToString(),
                oi.CreatedAt,
                oi.ExpiresAt,
                oi.IsAccepted,
                oi.EmailStatus.ToString(),
                oi.EmailAttemptCount,
                oi.LastEmailAttemptAt,
                oi.NextRetryAt,
                oi.LastEmailError
            ))
            .ToListAsync();

        return Ok(invitations);
    }

    /// <summary>
    /// Gets all pending invitations for an organization (requires Owner or Admin role)
    /// </summary>
    [HttpGet("{id}/invitations")]
    [ProducesResponseType(typeof(List<InvitationDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<List<InvitationDto>>> GetOrganizationInvitations(string id)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var membership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == id && om.UserId == userId);

        if (membership == null || (membership.Role != OrganizationRole.Owner && membership.Role != OrganizationRole.Admin))
            return Forbid();

        var invitations = await _invitationService.GetOrganizationInvitationsAsync(id);

        var response = invitations.Select(i => new InvitationDto(
            i.Id,
            i.OrganizationId,
            i.Organization.Name,
            i.Email,
            i.Role.ToString(),
            i.CreatedAt,
            i.ExpiresAt,
            i.IsAccepted,
            i.EmailStatus.ToString(),
            i.EmailAttemptCount,
            i.LastEmailAttemptAt,
            i.NextRetryAt,
            i.LastEmailError
        )).ToList();

        return Ok(response);
    }

    /// <summary>
    /// Resends an invitation email (requires Owner or Admin role)
    /// </summary>
    [HttpPost("{id}/invitations/{invitationId}/resend")]
    [ProducesResponseType(typeof(InvitationDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<InvitationDto>> ResendInvitation(string id, string invitationId)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var membership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == id && om.UserId == userId);

        if (membership == null || (membership.Role != OrganizationRole.Owner && membership.Role != OrganizationRole.Admin))
            return Forbid();

        var invitation = await _context.OrganizationInvitations
            .Include(i => i.Organization)
            .FirstOrDefaultAsync(i => i.Id == invitationId && i.OrganizationId == id);

        if (invitation == null)
            return NotFound(new { error = "Invitation not found" });

        var inviter = await _userManager.FindByIdAsync(userId);
        var (success, errorMessage) = await _invitationService.ResendInvitationEmailAsync(
            invitationId,
            inviter?.UserName ?? inviter?.Email
        );

        if (!success)
        {
            return BadRequest(new { error = errorMessage });
        }

        await _context.Entry(invitation).ReloadAsync();

        var response = new InvitationDto(
            invitation.Id,
            invitation.OrganizationId,
            invitation.Organization.Name,
            invitation.Email,
            invitation.Role.ToString(),
            invitation.CreatedAt,
            invitation.ExpiresAt,
            invitation.IsAccepted,
            invitation.EmailStatus.ToString(),
            invitation.EmailAttemptCount,
            invitation.LastEmailAttemptAt,
            invitation.NextRetryAt,
            invitation.LastEmailError
        );

        return Ok(response);
    }

    /// <summary>
    /// Revokes (cancels) a pending invitation before it is accepted (requires Owner or Admin role)
    /// </summary>
    [HttpDelete("{id}/invitations/{invitationId}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RevokeInvitation(string id, string invitationId)
    {
        var userId = GetCurrentUserId();
        if (userId == null) return Unauthorized();

        var membership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == id && om.UserId == userId);

        if (membership == null || (membership.Role != OrganizationRole.Owner && membership.Role != OrganizationRole.Admin))
            return Forbid();

        var invitation = await _context.OrganizationInvitations
            .FirstOrDefaultAsync(i => i.Id == invitationId && i.OrganizationId == id);

        if (invitation == null)
            return NotFound(new { error = "Invitation not found" });

        if (invitation.IsAccepted)
            return BadRequest(new { error = "Cannot revoke an invitation that has already been accepted" });

        _context.OrganizationInvitations.Remove(invitation);
        await _context.SaveChangesAsync();

        _logger.LogInformation("User {UserId} revoked invitation {InvitationId} for {Email} in organization {OrganizationId}",
            userId, invitationId, invitation.Email, id);

        return Ok(new { message = "Invitation revoked successfully" });
    }

    /// <summary>
    /// Removes a member from the organization (requires Owner or Admin role)
    /// </summary>
    [HttpDelete("{organizationId}/members/{userId}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveMember(string organizationId, string userId)
    {
        var currentUserId = GetCurrentUserId();
        if (currentUserId == null) return Unauthorized();

        var currentUserMembership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == organizationId && om.UserId == currentUserId);

        if (currentUserMembership == null)
            return NotFound(new { error = "Organization not found" });

        if (currentUserMembership.Role != OrganizationRole.Owner && currentUserMembership.Role != OrganizationRole.Admin)
            return Forbid();

        var targetMembership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == organizationId && om.UserId == userId);

        if (targetMembership == null)
            return NotFound(new { error = "Member not found" });

        // Cannot remove owners unless you are the owner
        if (targetMembership.Role == OrganizationRole.Owner && currentUserMembership.Role != OrganizationRole.Owner)
            return Forbid();

        // Cannot remove yourself if you're the only owner
        if (userId == currentUserId && currentUserMembership.Role == OrganizationRole.Owner)
        {
            var ownerCount = await _context.OrganizationMemberships
                .CountAsync(om => om.OrganizationId == organizationId && om.Role == OrganizationRole.Owner);

            if (ownerCount == 1)
                return BadRequest(new { error = "Cannot remove the only owner. Transfer ownership or delete the organization instead." });
        }

        _context.OrganizationMemberships.Remove(targetMembership);
        await _context.SaveChangesAsync();

        _logger.LogInformation("User {CurrentUserId} removed user {UserId} from organization {OrganizationId}", currentUserId, userId, organizationId);

        return Ok(new { message = "Member removed successfully" });
    }

    /// <summary>
    /// Leaves the organization (current user removes themselves)
    /// </summary>
    [HttpDelete("{organizationId}/members/me")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> LeaveOrganization(string organizationId)
    {
        var currentUserId = GetCurrentUserId();
        if (currentUserId == null) return Unauthorized();

        var membership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == organizationId && om.UserId == currentUserId);

        if (membership == null)
            return NotFound(new { error = "Organization not found" });

        if (membership.Role == OrganizationRole.Owner)
        {
            var ownerCount = await _context.OrganizationMemberships
                .CountAsync(om => om.OrganizationId == organizationId && om.Role == OrganizationRole.Owner);

            if (ownerCount == 1)
                return BadRequest(new { error = "You are the only owner. Transfer ownership to another member before leaving, or delete the organization." });
        }

        _context.OrganizationMemberships.Remove(membership);
        await _context.SaveChangesAsync();

        _logger.LogInformation("User {CurrentUserId} left organization {OrganizationId}", currentUserId, organizationId);

        return Ok(new { message = "You have left the organization" });
    }

    /// <summary>
    /// Updates a member's role in the organization (requires Owner role)
    /// </summary>
    [HttpPut("{organizationId}/members/{userId}/role")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateMemberRole(string organizationId, string userId, [FromBody] UpdateMemberRoleRequest request)
    {
        var currentUserId = GetCurrentUserId();
        if (currentUserId == null) return Unauthorized();

        var currentUserMembership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == organizationId && om.UserId == currentUserId);

        if (currentUserMembership == null)
            return NotFound(new { error = "Organization not found" });

        if (currentUserMembership.Role != OrganizationRole.Owner)
            return Forbid();

        var targetMembership = await _context.OrganizationMemberships
            .FirstOrDefaultAsync(om => om.OrganizationId == organizationId && om.UserId == userId);

        if (targetMembership == null)
            return NotFound(new { error = "Member not found" });

        if (!Enum.TryParse<OrganizationRole>(request.Role, true, out var newRole))
            return BadRequest(new { error = "Invalid role" });

        targetMembership.Role = newRole;
        await _context.SaveChangesAsync();

        _logger.LogInformation("User {CurrentUserId} updated role of user {UserId} in organization {OrganizationId} to {Role}",
            currentUserId, userId, organizationId, newRole);

        return Ok(new { message = "Member role updated successfully" });
    }
}
