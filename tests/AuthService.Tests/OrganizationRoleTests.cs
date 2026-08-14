using System.Net;
using System.Net.Http.Json;
using AuthService.Data;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The organization privilege boundary: who may grant what, and the guards that stop an
/// organization from ending up with nobody able to administer it.
/// </summary>
public class OrganizationRoleTests : IntegrationTestBase
{
    private async Task<string> CreateOrganizationAsync(TestTokens tokens, string name = "Acme")
    {
        Client.Authenticate(tokens);

        var response = await Client.PostAsJsonAsync("/api/v1/organizations", new { name });
        response.EnsureSuccessStatusCode();

        var org = await response.Content.ReadFromJsonAsync<OrgResponse>(TestData.Json);
        return org!.Id;
    }

    private async Task<string> GetUserIdAsync(TestTokens tokens)
    {
        Client.Authenticate(tokens);
        var me = await Client.GetAsync("/api/v1/auth/me");
        me.EnsureSuccessStatusCode();

        var profile = await me.Content.ReadFromJsonAsync<MeResponse>(TestData.Json);
        return profile!.Id;
    }

    /// <summary>Adds an existing user to an organization directly, bypassing the email flow.</summary>
    private async Task AddMemberAsync(string organizationId, string userId, OrganizationRole role)
    {
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            context.OrganizationMemberships.Add(new OrganizationMembership
            {
                OrganizationId = organizationId,
                UserId = userId,
                Role = role
            });
            await context.SaveChangesAsync();
        });
    }

    [Fact]
    public async Task The_sole_owner_cannot_demote_themselves()
    {
        var (_, owner) = await Client.RegisterAsync();
        var ownerId = await GetUserIdAsync(owner);
        var orgId = await CreateOrganizationAsync(owner);

        Client.Authenticate(owner);
        var response = await Client.PutAsJsonAsync(
            $"/api/v1/organizations/{orgId}/members/{ownerId}/role",
            new { role = "Member" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var membership = await context.OrganizationMemberships
                .SingleAsync(m => m.OrganizationId == orgId && m.UserId == ownerId);

            Assert.Equal(OrganizationRole.Owner, membership.Role);
        });
    }

    [Fact]
    public async Task An_owner_can_be_demoted_once_a_second_owner_exists()
    {
        var (_, owner) = await Client.RegisterAsync();
        var ownerId = await GetUserIdAsync(owner);
        var orgId = await CreateOrganizationAsync(owner);

        var (_, other) = await Client.RegisterAsync();
        var otherId = await GetUserIdAsync(other);
        await AddMemberAsync(orgId, otherId, OrganizationRole.Owner);

        Client.Authenticate(owner);
        var response = await Client.PutAsJsonAsync(
            $"/api/v1/organizations/{orgId}/members/{ownerId}/role",
            new { role = "Member" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task An_admin_cannot_invite_a_new_member_as_owner()
    {
        var (_, owner) = await Client.RegisterAsync();
        var orgId = await CreateOrganizationAsync(owner);

        var (_, admin) = await Client.RegisterAsync();
        var adminId = await GetUserIdAsync(admin);
        await AddMemberAsync(orgId, adminId, OrganizationRole.Admin);

        Client.Authenticate(admin);
        var asOwner = await Client.PostAsJsonAsync($"/api/v1/organizations/{orgId}/invite", new
        {
            email = TestData.NewEmail(),
            role = "Owner"
        });

        Assert.Equal(HttpStatusCode.Forbidden, asOwner.StatusCode);

        // The same admin may still invite at or below their own level.
        var asMember = await Client.PostAsJsonAsync($"/api/v1/organizations/{orgId}/invite", new
        {
            email = TestData.NewEmail(),
            role = "Member"
        });

        Assert.Equal(HttpStatusCode.OK, asMember.StatusCode);
    }

    [Fact]
    public async Task An_owner_can_invite_at_the_owner_role()
    {
        var (_, owner) = await Client.RegisterAsync();
        var orgId = await CreateOrganizationAsync(owner);

        Client.Authenticate(owner);
        var response = await Client.PostAsJsonAsync($"/api/v1/organizations/{orgId}/invite", new
        {
            email = TestData.NewEmail(),
            role = "Owner"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Transfer_ownership_promotes_the_target_and_steps_the_caller_down()
    {
        var (_, owner) = await Client.RegisterAsync();
        var ownerId = await GetUserIdAsync(owner);
        var orgId = await CreateOrganizationAsync(owner);

        var (_, successor) = await Client.RegisterAsync();
        var successorId = await GetUserIdAsync(successor);
        await AddMemberAsync(orgId, successorId, OrganizationRole.Member);

        Client.Authenticate(owner);
        var response = await Client.PostAsJsonAsync(
            $"/api/v1/organizations/{orgId}/transfer-ownership",
            new { toUserId = successorId });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();

            var newOwner = await context.OrganizationMemberships
                .SingleAsync(m => m.OrganizationId == orgId && m.UserId == successorId);
            var previousOwner = await context.OrganizationMemberships
                .SingleAsync(m => m.OrganizationId == orgId && m.UserId == ownerId);

            Assert.Equal(OrganizationRole.Owner, newOwner.Role);
            Assert.Equal(OrganizationRole.Admin, previousOwner.Role);

            // Exactly one Owner at all times.
            var owners = await context.OrganizationMemberships
                .CountAsync(m => m.OrganizationId == orgId && m.Role == OrganizationRole.Owner);
            Assert.Equal(1, owners);
        });
    }

    [Fact]
    public async Task Transfer_ownership_requires_the_target_to_be_a_member()
    {
        var (_, owner) = await Client.RegisterAsync();
        var orgId = await CreateOrganizationAsync(owner);

        var (_, outsider) = await Client.RegisterAsync();
        var outsiderId = await GetUserIdAsync(outsider);

        Client.Authenticate(owner);
        var response = await Client.PostAsJsonAsync(
            $"/api/v1/organizations/{orgId}/transfer-ownership",
            new { toUserId = outsiderId });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task A_plain_member_cannot_change_roles()
    {
        var (_, owner) = await Client.RegisterAsync();
        var ownerId = await GetUserIdAsync(owner);
        var orgId = await CreateOrganizationAsync(owner);

        var (_, member) = await Client.RegisterAsync();
        var memberId = await GetUserIdAsync(member);
        await AddMemberAsync(orgId, memberId, OrganizationRole.Member);

        Client.Authenticate(member);
        var response = await Client.PutAsJsonAsync(
            $"/api/v1/organizations/{orgId}/members/{ownerId}/role",
            new { role = "Member" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private record OrgResponse(string Id, string Name);
    private record MeResponse(string Id, string Email);
}
