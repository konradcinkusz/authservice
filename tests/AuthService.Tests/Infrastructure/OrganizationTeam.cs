using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Data;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Tests.Infrastructure;

/// <summary>The positions the organization capability table in docs/roles.md distinguishes.</summary>
public enum Who { Owner, Admin, Member, Outsider }

/// <summary>
/// One organization and a person in each position relative to it: an Owner, an Admin, a Member
/// and someone who does not belong. Each has a client of their own, so a test reads as the table
/// does — who does what — without swapping credentials on one client.
/// </summary>
public sealed class OrganizationTeam
{
    private readonly Dictionary<Who, (TestAccount Account, HttpClient Client)> _people;

    internal OrganizationTeam(
        string id, string name, IEnumerable<(Who Who, TestAccount Account, HttpClient Client)> people)
    {
        Id = id;
        Name = name;
        _people = people.ToDictionary(p => p.Who, p => (p.Account, p.Client));
    }

    public string Id { get; }
    public string Name { get; }

    public TestAccount this[Who who] => _people[who].Account;
    public HttpClient As(Who who) => _people[who].Client;

    public TestAccount Owner => this[Who.Owner];
    public TestAccount Admin => this[Who.Admin];
    public TestAccount Member => this[Who.Member];
    public TestAccount Outsider => this[Who.Outsider];

    public string Url(string path = "") => $"/api/v1/organizations/{Id}{path}";
}

public static class TestOrganizations
{
    public static async Task<OrganizationTeam> CreateTeamAsync(this AuthServiceFactory factory, string name = "Acme")
    {
        var owner = await factory.CreateAccountAsync();
        var admin = await factory.CreateAccountAsync();
        var member = await factory.CreateAccountAsync();
        var outsider = await factory.CreateAccountAsync();

        var id = await factory.ClientFor(owner.Tokens).CreateOrganizationAsync(name);
        await factory.AddMemberAsync(id, admin.Id, OrganizationRole.Admin);
        await factory.AddMemberAsync(id, member.Id, OrganizationRole.Member);

        return new OrganizationTeam(id, name,
        [
            (Who.Owner, owner, factory.ClientFor(owner.Tokens)),
            (Who.Admin, admin, factory.ClientFor(admin.Tokens)),
            (Who.Member, member, factory.ClientFor(member.Tokens)),
            (Who.Outsider, outsider, factory.ClientFor(outsider.Tokens))
        ]);
    }

    public static async Task<string> CreateOrganizationAsync(this HttpClient client, string name = "Acme")
    {
        var response = await client.PostAsJsonAsync("/api/v1/organizations", new { name });
        response.EnsureSuccessStatusCode();

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("id").GetString()!;
    }

    /// <summary>Makes an existing user a member directly, bypassing the invitation flow.</summary>
    public static Task AddMemberAsync(
        this AuthServiceFactory factory, string organizationId, string userId, OrganizationRole role) =>
        factory.WithScopeAsync(async services =>
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

    /// <summary>The role the user holds in the organization, or null when they are not a member.</summary>
    public static async Task<OrganizationRole?> RoleInAsync(
        this AuthServiceFactory factory, string organizationId, string userId)
    {
        OrganizationRole? role = null;

        await factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var membership = await context.OrganizationMemberships.IgnoreQueryFilters().AsNoTracking()
                .SingleOrDefaultAsync(m => m.OrganizationId == organizationId && m.UserId == userId);
            role = membership?.Role;
        });

        return role;
    }

    /// <summary>The stored organization, deleted or not, or null once it is gone.</summary>
    public static async Task<Organization?> StoredOrganizationAsync(this AuthServiceFactory factory, string organizationId)
    {
        Organization? organization = null;

        await factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            organization = await context.Organizations.IgnoreQueryFilters().AsNoTracking()
                .SingleOrDefaultAsync(o => o.Id == organizationId);
        });

        return organization;
    }

    /// <summary>Every invitation the organization has, whatever its state, oldest first.</summary>
    public static async Task<List<OrganizationInvitation>> StoredInvitationsAsync(
        this AuthServiceFactory factory, string organizationId)
    {
        List<OrganizationInvitation> invitations = [];

        await factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            invitations = (await context.OrganizationInvitations.AsNoTracking().Include(i => i.EmailAttempts)
                    .Where(i => i.OrganizationId == organizationId).ToListAsync())
                .OrderBy(i => i.CreatedAt).ToList();
        });

        return invitations;
    }

    /// <summary>Changes a stored invitation directly, for the states time or other actors would produce.</summary>
    public static Task UpdateInvitationAsync(
        this AuthServiceFactory factory, string invitationId, Action<OrganizationInvitation> change) =>
        factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var invitation = await context.OrganizationInvitations.SingleAsync(i => i.Id == invitationId);
            change(invitation);
            await context.SaveChangesAsync();
        });
}
