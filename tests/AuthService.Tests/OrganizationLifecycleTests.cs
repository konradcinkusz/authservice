using System.Net;
using System.Net.Http.Json;
using AuthService.DTOs;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// An organization from creation to permanent deletion, against the capability table in
/// <c>docs/roles.md</c>: who may see it, change it, delete it and bring it back.
/// </summary>
public class OrganizationLifecycleTests : IntegrationTestBase
{
    private const string Organizations = "/api/v1/organizations";

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<T>(TestData.Json))!;

    private static async Task<List<OrganizationDto>> ListAsync(HttpClient client)
    {
        var response = await client.GetAsync(Organizations);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return await ReadAsync<List<OrganizationDto>>(response);
    }

    private static async Task SoftDeleteAsync(OrganizationTeam team) =>
        (await team.As(Who.Owner).DeleteAsync(team.Url())).EnsureSuccessStatusCode();

    private static void AssertNear(DateTime? actual, DateTime expected, TimeSpan tolerance)
    {
        Assert.NotNull(actual);
        Assert.InRange(actual.Value, expected - tolerance, expected + tolerance);
    }

    // ─── Signed in, or nothing ───────────────────────────────────────────────

    public static TheoryData<string, string> Endpoints => new()
    {
        { "GET", Organizations },
        { "POST", Organizations },
        { "GET", $"{Organizations}/some-org" },
        { "PUT", $"{Organizations}/some-org" },
        { "DELETE", $"{Organizations}/some-org" },
        { "POST", $"{Organizations}/some-org/restore" },
        { "DELETE", $"{Organizations}/some-org/hard" },
        { "POST", $"{Organizations}/some-org/invite" },
        { "POST", $"{Organizations}/invitations/accept" },
        { "GET", $"{Organizations}/invitations" },
        { "GET", $"{Organizations}/some-org/invitations" },
        { "POST", $"{Organizations}/some-org/invitations/some-invitation/resend" },
        { "DELETE", $"{Organizations}/some-org/invitations/some-invitation" },
        { "DELETE", $"{Organizations}/some-org/members/some-user" },
        { "DELETE", $"{Organizations}/some-org/members/me" },
        { "PUT", $"{Organizations}/some-org/members/some-user/role" },
        { "POST", $"{Organizations}/some-org/transfer-ownership" },
    };

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task Every_organization_endpoint_needs_a_signed_in_user(string method, string url)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), url);
        if (method is "POST" or "PUT")
            request.Content = JsonContent.Create(new { });

        var response = await Factory.ClientFor().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task The_unversioned_route_still_answers_for_consumers_that_have_not_moved()
    {
        var account = await Factory.CreateAccountAsync();
        await Factory.ClientFor(account.Tokens).CreateOrganizationAsync("Legacy");

        var response = await Factory.ClientFor(account.Tokens).GetAsync("/api/organizations");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Legacy", Assert.Single(await ReadAsync<List<OrganizationDto>>(response)).Name);
    }

    // ─── Creating ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Creating_an_organization_makes_the_creator_its_only_owner()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);

        var response = await client.PostAsJsonAsync(Organizations, new
        {
            name = "Acme",
            description = "Roadrunner supplies",
            imageUrl = "https://example.test/acme.png"
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await ReadAsync<OrganizationDto>(response);
        Assert.Equal("Acme", created.Name);
        Assert.Equal("Roadrunner supplies", created.Description);
        Assert.Equal("https://example.test/acme.png", created.ImageUrl);
        Assert.Equal(1, created.MemberCount);
        Assert.Equal("Owner", created.UserRole);
        Assert.False(created.IsDeleted);
        Assert.EndsWith($"/{created.Id}", response.Headers.Location!.ToString());

        Assert.Equal(OrganizationRole.Owner, await Factory.RoleInAsync(created.Id, account.Id));
        Assert.Equal(account.Id, (await Factory.StoredOrganizationAsync(created.Id))!.CreatedByUserId);

        var audit = Assert.Single(await Factory.AuditAsync(AuditAction.OrganizationCreated));
        Assert.Equal(account.Id, audit.ActorUserId);
        Assert.Equal(created.Id, audit.TargetOrganizationId);
        Assert.Contains("Acme", audit.Metadata);
    }

    public static TheoryData<string?, string?, string?> InvalidOrganizations => new()
    {
        { null, null, null },
        { "", null, null },
        { new string('x', 101), null, null },
        { "Acme", new string('x', 501), null },
        { "Acme", null, "not a url" },
        { "Acme", null, $"https://example.test/{new string('a', 500)}" },
    };

    [Theory]
    [MemberData(nameof(InvalidOrganizations))]
    public async Task An_organization_that_breaks_the_limits_is_refused_with_the_reasons(
        string? name, string? description, string? imageUrl)
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);

        var response = await client.PostAsJsonAsync(Organizations, new { name, description, imageUrl });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True((await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>()).TryGetProperty("errors", out _));
        Assert.Empty(await ListAsync(client));
    }

    // ─── Seeing ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Owner, "Owner")]
    [InlineData(Who.Admin, "Admin")]
    [InlineData(Who.Member, "Member")]
    [InlineData(Who.Outsider, null)]
    public async Task The_list_holds_the_organizations_a_person_belongs_to_with_their_own_role(Who who, string? role)
    {
        var team = await Factory.CreateTeamAsync();

        var organizations = await ListAsync(team.As(who));

        if (role is null)
        {
            Assert.Empty(organizations);
            return;
        }

        var listed = Assert.Single(organizations);
        Assert.Equal(team.Id, listed.Id);
        Assert.Equal(role, listed.UserRole);
        Assert.Equal(3, listed.MemberCount);
    }

    [Fact]
    public async Task The_list_is_in_the_order_the_person_joined()
    {
        var team = await Factory.CreateTeamAsync("First");
        await team.As(Who.Owner).CreateOrganizationAsync("Second");
        await team.As(Who.Owner).CreateOrganizationAsync("Third");

        var organizations = await ListAsync(team.As(Who.Owner));

        Assert.Equal(["First", "Second", "Third"], organizations.Select(o => o.Name));
    }

    [Theory]
    [InlineData(Who.Owner, HttpStatusCode.OK)]
    [InlineData(Who.Admin, HttpStatusCode.OK)]
    [InlineData(Who.Member, HttpStatusCode.OK)]
    [InlineData(Who.Outsider, HttpStatusCode.NotFound)]
    public async Task Any_member_can_view_the_organization_and_nobody_else_can(Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();

        var response = await team.As(who).GetAsync(team.Url());

        Assert.Equal(expected, response.StatusCode);
    }

    [Fact]
    public async Task The_detail_names_every_member_with_their_role()
    {
        var team = await Factory.CreateTeamAsync();
        await team.As(Who.Owner).PutAsJsonAsync(team.Url(), new
        {
            name = "Acme",
            description = "Roadrunner supplies",
            imageUrl = "https://example.test/acme.png"
        });

        var detail = await ReadAsync<OrganizationDetailDto>(await team.As(Who.Member).GetAsync(team.Url()));

        Assert.Equal(team.Id, detail.Id);
        Assert.Equal("Roadrunner supplies", detail.Description);
        Assert.Equal("https://example.test/acme.png", detail.ImageUrl);
        Assert.Equal(
            new[] { (team.Owner.Id, "Owner"), (team.Admin.Id, "Admin"), (team.Member.Id, "Member") }.Order(),
            detail.Members.Select(m => (m.UserId, m.Role)).Order());
        Assert.Equal(team.Admin.Email, detail.Members.Single(m => m.UserId == team.Admin.Id).Email);
    }

    [Fact]
    public async Task A_platform_super_admin_has_no_rights_inside_an_organization_they_do_not_belong_to()
    {
        var team = await Factory.CreateTeamAsync();
        var superAdmin = Factory.ClientFor((await Factory.CreateAccountAsync(TestUsers.SuperAdmin)).Tokens);

        var attempts = new[]
        {
            await superAdmin.GetAsync(team.Url()),
            await superAdmin.PutAsJsonAsync(team.Url(), new { name = "Taken over" }),
            await superAdmin.DeleteAsync(team.Url()),
            await superAdmin.PostAsJsonAsync(team.Url("/invite"), new { email = TestData.NewEmail() }),
            await superAdmin.GetAsync(team.Url("/invitations")),
            await superAdmin.PutAsJsonAsync(team.Url($"/members/{team.Member.Id}/role"), new { role = "Owner" }),
            await superAdmin.DeleteAsync(team.Url($"/members/{team.Member.Id}")),
            await superAdmin.PostAsJsonAsync(team.Url("/transfer-ownership"), new { toUserId = team.Member.Id }),
        };

        Assert.All(attempts, r => Assert.True(r.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
            $"{r.RequestMessage!.Method} {r.RequestMessage.RequestUri!.AbsolutePath} answered {(int)r.StatusCode}"));
        var stored = await Factory.StoredOrganizationAsync(team.Id);
        Assert.Equal("Acme", stored!.Name);
        Assert.False(stored.IsDeleted);
        Assert.Equal(OrganizationRole.Member, await Factory.RoleInAsync(team.Id, team.Member.Id));
    }

    // ─── Updating ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Owner, HttpStatusCode.OK)]
    [InlineData(Who.Admin, HttpStatusCode.OK)]
    [InlineData(Who.Member, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, HttpStatusCode.Forbidden)]
    public async Task Owners_and_admins_can_update_the_organization(Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();

        var response = await team.As(who).PutAsJsonAsync(team.Url(), new
        {
            name = "Renamed",
            description = "New text",
            imageUrl = "https://example.test/new.png"
        });

        Assert.Equal(expected, response.StatusCode);
        var stored = (await Factory.StoredOrganizationAsync(team.Id))!;
        if (expected == HttpStatusCode.OK)
        {
            Assert.Equal(("Renamed", "New text", "https://example.test/new.png"), (stored.Name, stored.Description, stored.ImageUrl));
        }
        else
        {
            Assert.Equal("Acme", stored.Name);
            Assert.Null(stored.Description);
        }
    }

    [Fact]
    public async Task An_update_replaces_name_description_and_image_together()
    {
        var team = await Factory.CreateTeamAsync();
        await team.As(Who.Owner).PutAsJsonAsync(team.Url(),
            new { name = "Acme", description = "Roadrunner supplies", imageUrl = "https://example.test/acme.png" });

        var response = await team.As(Who.Owner).PutAsJsonAsync(team.Url(), new { name = "Only a name" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var stored = (await Factory.StoredOrganizationAsync(team.Id))!;
        Assert.Equal("Only a name", stored.Name);
        Assert.Null(stored.Description);
        Assert.Null(stored.ImageUrl);
    }

    [Fact]
    public async Task An_update_that_breaks_the_limits_is_refused_and_changes_nothing()
    {
        var team = await Factory.CreateTeamAsync();

        var response = await team.As(Who.Owner).PutAsJsonAsync(team.Url(), new { name = "" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("Acme", (await Factory.StoredOrganizationAsync(team.Id))!.Name);
    }

    // ─── Deleting ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Owner, HttpStatusCode.OK)]
    [InlineData(Who.Admin, HttpStatusCode.Forbidden)]
    [InlineData(Who.Member, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, HttpStatusCode.Forbidden)]
    public async Task Only_an_owner_can_delete_the_organization(Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();

        var response = await team.As(who).DeleteAsync(team.Url());

        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(expected == HttpStatusCode.OK, (await Factory.StoredOrganizationAsync(team.Id))!.IsDeleted);
    }

    [Fact]
    public async Task Deleting_schedules_permanent_removal_and_records_who_did_it()
    {
        var team = await Factory.CreateTeamAsync();

        var response = await team.As(Who.Owner).DeleteAsync(team.Url());

        var body = await ReadAsync<System.Text.Json.JsonElement>(response);
        Assert.Equal(Organization.DefaultRetentionDays, body.GetProperty("retentionDays").GetInt32());
        var scheduled = body.GetProperty("scheduledPermanentDeletionAt").GetDateTime();
        AssertNear(scheduled, DateTime.UtcNow.AddDays(Organization.DefaultRetentionDays), TimeSpan.FromMinutes(1));

        var stored = (await Factory.StoredOrganizationAsync(team.Id))!;
        Assert.True(stored.IsDeleted);
        Assert.Equal(team.Owner.Id, stored.DeletedByUserId);
        AssertNear(stored.DeletedAt, DateTime.UtcNow, TimeSpan.FromMinutes(1));
        Assert.Equal(scheduled, stored.ScheduledPermanentDeletionAt);

        var audit = Assert.Single(await Factory.AuditAsync(AuditAction.OrganizationDeleted));
        Assert.Equal(team.Owner.Id, audit.ActorUserId);
        Assert.Equal(team.Id, audit.TargetOrganizationId);
    }

    [Fact]
    public async Task A_deleted_organization_leaves_everyones_list_but_the_owners()
    {
        var team = await Factory.CreateTeamAsync();

        await SoftDeleteAsync(team);

        Assert.Empty(await ListAsync(team.As(Who.Admin)));
        Assert.Empty(await ListAsync(team.As(Who.Member)));
        var listed = Assert.Single(await ListAsync(team.As(Who.Owner)));
        Assert.Equal(team.Id, listed.Id);
        Assert.True(listed.IsDeleted);
        Assert.NotNull(listed.ScheduledPermanentDeletionAt);
        Assert.Equal(3, listed.MemberCount);
    }

    [Fact]
    public async Task A_deleted_organization_cannot_be_edited_or_invited_into()
    {
        var team = await Factory.CreateTeamAsync();
        await SoftDeleteAsync(team);
        var invitee = TestData.NewEmail("invitee");

        var update = await team.As(Who.Owner).PutAsJsonAsync(team.Url(), new { name = "Renamed" });
        var invite = await team.As(Who.Owner).PostAsJsonAsync(team.Url("/invite"), new { email = invitee });

        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, invite.StatusCode);
        Assert.Equal("Acme", (await Factory.StoredOrganizationAsync(team.Id))!.Name);
        Assert.Empty(await Factory.StoredInvitationsAsync(team.Id));
        Assert.Empty(Factory.Emails.To(invitee));
    }

    // ─── Restoring ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Owner, HttpStatusCode.OK)]
    [InlineData(Who.Admin, HttpStatusCode.Forbidden)]
    [InlineData(Who.Member, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, HttpStatusCode.Forbidden)]
    public async Task Only_an_owner_can_restore_a_deleted_organization(Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();
        await SoftDeleteAsync(team);

        var response = await team.As(who).PostAsync(team.Url("/restore"), null);

        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(expected != HttpStatusCode.OK, (await Factory.StoredOrganizationAsync(team.Id))!.IsDeleted);
    }

    [Fact]
    public async Task Restoring_brings_back_the_organization_with_its_members()
    {
        var team = await Factory.CreateTeamAsync();
        await SoftDeleteAsync(team);

        (await team.As(Who.Owner).PostAsync(team.Url("/restore"), null)).EnsureSuccessStatusCode();

        var stored = (await Factory.StoredOrganizationAsync(team.Id))!;
        Assert.False(stored.IsDeleted);
        Assert.Null(stored.DeletedAt);
        Assert.Null(stored.DeletedByUserId);
        Assert.Null(stored.ScheduledPermanentDeletionAt);
        foreach (var who in new[] { Who.Owner, Who.Admin, Who.Member })
        {
            var listed = Assert.Single(await ListAsync(team.As(who)));
            Assert.False(listed.IsDeleted);
            Assert.Equal(3, listed.MemberCount);
        }

        var audit = Assert.Single(await Factory.AuditAsync(AuditAction.OrganizationRestored));
        Assert.Equal(team.Owner.Id, audit.ActorUserId);
        Assert.Equal(team.Id, audit.TargetOrganizationId);
    }

    [Fact]
    public async Task Only_a_deleted_organization_can_be_restored()
    {
        var team = await Factory.CreateTeamAsync();

        var live = await team.As(Who.Owner).PostAsync(team.Url("/restore"), null);
        var unknown = await team.As(Who.Owner).PostAsync($"{Organizations}/no-such-org/restore", null);

        Assert.Equal(HttpStatusCode.NotFound, live.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Empty(await Factory.AuditAsync(AuditAction.OrganizationRestored));
    }

    // ─── Deleting for good ───────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Owner, HttpStatusCode.OK)]
    [InlineData(Who.Admin, HttpStatusCode.Forbidden)]
    [InlineData(Who.Member, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, HttpStatusCode.Forbidden)]
    public async Task Only_an_owner_can_delete_a_deleted_organization_for_good(Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();
        await SoftDeleteAsync(team);

        var response = await team.As(who).DeleteAsync(team.Url("/hard"));

        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(expected != HttpStatusCode.OK, await Factory.StoredOrganizationAsync(team.Id) is not null);
    }

    [Fact]
    public async Task Deleting_for_good_takes_the_members_and_invitations_with_it()
    {
        var team = await Factory.CreateTeamAsync();
        (await team.As(Who.Owner).PostAsJsonAsync(team.Url("/invite"), new { email = TestData.NewEmail() }))
            .EnsureSuccessStatusCode();
        await SoftDeleteAsync(team);

        (await team.As(Who.Owner).DeleteAsync(team.Url("/hard"))).EnsureSuccessStatusCode();

        Assert.Null(await Factory.StoredOrganizationAsync(team.Id));
        Assert.Empty(await Factory.StoredInvitationsAsync(team.Id));
        foreach (var who in new[] { Who.Owner, Who.Admin, Who.Member })
        {
            Assert.Null(await Factory.RoleInAsync(team.Id, team[who].Id));
            Assert.Empty(await ListAsync(team.As(who)));
        }

        Assert.Equal(HttpStatusCode.NotFound, (await team.As(Who.Owner).GetAsync(team.Url())).StatusCode);
        var audit = Assert.Single(await Factory.AuditAsync(AuditAction.OrganizationHardDeleted));
        Assert.Equal(team.Owner.Id, audit.ActorUserId);
        Assert.Contains("Acme", audit.Metadata);
    }

    [Fact]
    public async Task An_organization_that_is_not_deleted_cannot_be_deleted_for_good()
    {
        var team = await Factory.CreateTeamAsync();

        var live = await team.As(Who.Owner).DeleteAsync(team.Url("/hard"));
        var unknown = await team.As(Who.Owner).DeleteAsync($"{Organizations}/no-such-org/hard");

        Assert.Equal(HttpStatusCode.NotFound, live.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.NotNull(await Factory.StoredOrganizationAsync(team.Id));
        Assert.Empty(await Factory.AuditAsync(AuditAction.OrganizationHardDeleted));
    }
}
