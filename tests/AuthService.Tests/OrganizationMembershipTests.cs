using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Who may remove a member, leave, change a role or hand the organization over, and the rule
/// under all of them: it never ends up with nobody to administer it. The role table and the
/// guards are in <c>docs/roles.md</c>; <see cref="OrganizationRoleTests"/> holds the first few
/// of these, and this class is the rest.
/// </summary>
public class OrganizationMembershipTests : IntegrationTestBase
{
    private static async Task<string> ErrorAsync(HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString()!;

    private static Task<HttpResponseMessage> RemoveAsync(HttpClient client, OrganizationTeam team, string userId) =>
        client.DeleteAsync(team.Url($"/members/{userId}"));

    private static Task<HttpResponseMessage> LeaveAsync(HttpClient client, OrganizationTeam team) =>
        client.DeleteAsync(team.Url("/members/me"));

    private static Task<HttpResponseMessage> SetRoleAsync(HttpClient client, OrganizationTeam team, string userId, string role) =>
        client.PutAsJsonAsync(team.Url($"/members/{userId}/role"), new { role });

    private static Task<HttpResponseMessage> TransferAsync(
        HttpClient client, OrganizationTeam team, string toUserId, bool? retainAdminRole = null) =>
        client.PostAsJsonAsync(team.Url("/transfer-ownership"),
            retainAdminRole is null ? new { toUserId } : (object)new { toUserId, retainAdminRole });

    private async Task<int> OwnerCountAsync(OrganizationTeam team)
    {
        var roles = new List<OrganizationRole?>();
        foreach (var who in new[] { Who.Owner, Who.Admin, Who.Member, Who.Outsider })
            roles.Add(await Factory.RoleInAsync(team.Id, team[who].Id));

        return roles.Count(role => role == OrganizationRole.Owner);
    }

    // ─── Removing a member ───────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Owner, Who.Member, HttpStatusCode.OK)]
    [InlineData(Who.Owner, Who.Admin, HttpStatusCode.OK)]
    [InlineData(Who.Admin, Who.Member, HttpStatusCode.OK)]
    [InlineData(Who.Admin, Who.Owner, HttpStatusCode.Forbidden)]
    [InlineData(Who.Member, Who.Admin, HttpStatusCode.Forbidden)]
    [InlineData(Who.Member, Who.Owner, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, Who.Member, HttpStatusCode.NotFound)]
    public async Task Who_can_remove_whom(Who actor, Who target, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();

        var response = await RemoveAsync(team.As(actor), team, team[target].Id);

        Assert.Equal(expected, response.StatusCode);
        var stillThere = await Factory.RoleInAsync(team.Id, team[target].Id) is not null;
        Assert.Equal(expected != HttpStatusCode.OK, stillThere);
    }

    [Fact]
    public async Task Removing_a_member_records_who_did_it_and_the_role_they_held()
    {
        var team = await Factory.CreateTeamAsync();

        (await RemoveAsync(team.As(Who.Admin), team, team.Member.Id)).EnsureSuccessStatusCode();

        var audit = Assert.Single(await Factory.AuditAsync(AuditAction.OrgMemberRemoved));
        Assert.Equal(team.Admin.Id, audit.ActorUserId);
        Assert.Equal(team.Member.Id, audit.TargetUserId);
        Assert.Equal(team.Id, audit.TargetOrganizationId);
        Assert.Contains("Member", audit.Metadata);
    }

    [Fact]
    public async Task A_removed_member_no_longer_sees_the_organization()
    {
        var team = await Factory.CreateTeamAsync();

        (await RemoveAsync(team.As(Who.Owner), team, team.Member.Id)).EnsureSuccessStatusCode();

        Assert.Equal(HttpStatusCode.NotFound, (await team.As(Who.Member).GetAsync(team.Url())).StatusCode);
        var organizations = await team.As(Who.Member).GetFromJsonAsync<JsonElement>("/api/v1/organizations");
        Assert.Equal(0, organizations.GetArrayLength());
    }

    [Fact]
    public async Task Removing_someone_who_is_not_a_member_finds_nobody()
    {
        var team = await Factory.CreateTeamAsync();

        var outsider = await RemoveAsync(team.As(Who.Owner), team, team.Outsider.Id);
        var unknown = await RemoveAsync(team.As(Who.Owner), team, "no-such-user");

        Assert.Equal(HttpStatusCode.NotFound, outsider.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Empty(await Factory.AuditAsync(AuditAction.OrgMemberRemoved));
    }

    [Fact]
    public async Task The_only_owner_cannot_be_removed_even_by_themselves()
    {
        var team = await Factory.CreateTeamAsync();

        var response = await RemoveAsync(team.As(Who.Owner), team, team.Owner.Id);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("only owner", await ErrorAsync(response));
        Assert.Equal(OrganizationRole.Owner, await Factory.RoleInAsync(team.Id, team.Owner.Id));
    }

    [Fact]
    public async Task An_owner_can_remove_another_owner_but_not_the_last_one_that_is_left()
    {
        var team = await Factory.CreateTeamAsync();
        await SetRoleAsync(team.As(Who.Owner), team, team.Admin.Id, "Owner");

        var removed = await RemoveAsync(team.As(Who.Owner), team, team.Admin.Id);
        var last = await RemoveAsync(team.As(Who.Owner), team, team.Owner.Id);

        Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, last.StatusCode);
        Assert.Equal(1, await OwnerCountAsync(team));
    }

    // ─── Leaving ─────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Admin)]
    [InlineData(Who.Member)]
    public async Task An_admin_or_member_can_leave(Who who)
    {
        var team = await Factory.CreateTeamAsync();

        var response = await LeaveAsync(team.As(who), team);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(await Factory.RoleInAsync(team.Id, team[who].Id));
        var audit = Assert.Single(await Factory.AuditAsync(AuditAction.OrgMemberRemoved));
        Assert.Equal(team[who].Id, audit.ActorUserId);
        Assert.Equal(team[who].Id, audit.TargetUserId);
        Assert.Contains("left", audit.Metadata);
    }

    [Fact]
    public async Task An_owner_can_leave_once_there_is_another_owner_but_the_last_one_cannot()
    {
        var team = await Factory.CreateTeamAsync();

        var sole = await LeaveAsync(team.As(Who.Owner), team);
        await SetRoleAsync(team.As(Who.Owner), team, team.Admin.Id, "Owner");
        var shared = await LeaveAsync(team.As(Who.Owner), team);
        var last = await LeaveAsync(team.As(Who.Admin), team);

        Assert.Equal(HttpStatusCode.BadRequest, sole.StatusCode);
        Assert.Contains("only owner", await ErrorAsync(sole));
        Assert.Equal(HttpStatusCode.OK, shared.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, last.StatusCode);
        Assert.Equal(OrganizationRole.Owner, await Factory.RoleInAsync(team.Id, team.Admin.Id));
    }

    [Fact]
    public async Task Leaving_an_organization_you_do_not_belong_to_finds_nothing()
    {
        var team = await Factory.CreateTeamAsync();

        var response = await LeaveAsync(team.As(Who.Outsider), team);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(await Factory.AuditAsync(AuditAction.OrgMemberRemoved));
    }

    // ─── Changing a role ─────────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Owner, HttpStatusCode.OK)]
    [InlineData(Who.Admin, HttpStatusCode.Forbidden)]
    [InlineData(Who.Member, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, HttpStatusCode.NotFound)]
    public async Task Only_an_owner_can_change_a_role(Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();

        var response = await SetRoleAsync(team.As(who), team, team.Member.Id, "Admin");

        Assert.Equal(expected, response.StatusCode);
        var role = expected == HttpStatusCode.OK ? OrganizationRole.Admin : OrganizationRole.Member;
        Assert.Equal(role, await Factory.RoleInAsync(team.Id, team.Member.Id));
    }

    [Theory]
    [InlineData("Admin")]
    [InlineData("Owner")]
    public async Task A_role_change_is_recorded_with_where_it_came_from_and_went_to(string newRole)
    {
        var team = await Factory.CreateTeamAsync();

        (await SetRoleAsync(team.As(Who.Owner), team, team.Member.Id, newRole)).EnsureSuccessStatusCode();

        var audit = Assert.Single(await Factory.AuditAsync(AuditAction.OrgMemberRoleChanged));
        Assert.Equal(team.Owner.Id, audit.ActorUserId);
        Assert.Equal(team.Member.Id, audit.TargetUserId);
        Assert.Equal(team.Id, audit.TargetOrganizationId);
        using var metadata = JsonDocument.Parse(audit.Metadata!);
        Assert.Equal("Member", metadata.RootElement.GetProperty("from").GetString());
        Assert.Equal(newRole, metadata.RootElement.GetProperty("to").GetString());
    }

    [Fact]
    public async Task Setting_the_role_a_member_already_has_succeeds_and_records_nothing()
    {
        var team = await Factory.CreateTeamAsync();

        var response = await SetRoleAsync(team.As(Who.Owner), team, team.Admin.Id, "Admin");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(await Factory.AuditAsync(AuditAction.OrgMemberRoleChanged));
    }

    [Fact]
    public async Task A_role_change_reaches_the_members_token_when_the_next_one_is_issued()
    {
        var team = await Factory.CreateTeamAsync();
        var before = await Factory.ClientFor().LoginAsync(team.Member.Email);

        (await SetRoleAsync(team.As(Who.Owner), team, team.Member.Id, "Admin")).EnsureSuccessStatusCode();
        var refreshed = await Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = before.RefreshToken });

        Assert.Equal("Member", before.OrganizationRole(team.Id));
        Assert.Equal("Admin", (await refreshed.Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!.OrganizationRole(team.Id));
    }

    [Fact]
    public async Task A_role_change_finds_nobody_when_the_target_is_not_a_member()
    {
        var team = await Factory.CreateTeamAsync();

        var outsider = await SetRoleAsync(team.As(Who.Owner), team, team.Outsider.Id, "Admin");
        var unknown = await SetRoleAsync(team.As(Who.Owner), team, "no-such-user", "Admin");

        Assert.Equal(HttpStatusCode.NotFound, outsider.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Null(await Factory.RoleInAsync(team.Id, team.Outsider.Id));
    }

    [Theory]
    [InlineData("Superuser")]
    [InlineData("")]
    public async Task A_role_that_does_not_exist_is_refused(string role)
    {
        var team = await Factory.CreateTeamAsync();

        var response = await SetRoleAsync(team.As(Who.Owner), team, team.Member.Id, role);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(OrganizationRole.Member, await Factory.RoleInAsync(team.Id, team.Member.Id));
    }

    [Fact]
    public async Task The_last_owner_cannot_be_demoted_however_many_others_were_demoted_before()
    {
        var team = await Factory.CreateTeamAsync();
        await SetRoleAsync(team.As(Who.Owner), team, team.Admin.Id, "Owner");
        await SetRoleAsync(team.As(Who.Owner), team, team.Member.Id, "Owner");

        var first = await SetRoleAsync(team.As(Who.Owner), team, team.Member.Id, "Member");
        var second = await SetRoleAsync(team.As(Who.Owner), team, team.Admin.Id, "Admin");
        var last = await SetRoleAsync(team.As(Who.Owner), team, team.Owner.Id, "Admin");

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, last.StatusCode);
        Assert.Contains("only owner", await ErrorAsync(last));
        Assert.Equal(1, await OwnerCountAsync(team));
    }

    // ─── Handing the organization over ───────────────────────────────────────

    [Theory]
    [InlineData(null, OrganizationRole.Admin)]
    [InlineData(true, OrganizationRole.Admin)]
    [InlineData(false, OrganizationRole.Member)]
    public async Task The_outgoing_owner_keeps_admin_unless_they_ask_to_step_all_the_way_down(
        bool? retainAdminRole, OrganizationRole expectedRole)
    {
        var team = await Factory.CreateTeamAsync();

        var response = await TransferAsync(team.As(Who.Owner), team, team.Member.Id, retainAdminRole);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(team.Member.Id, body.GetProperty("newOwnerUserId").GetString());
        Assert.Equal(expectedRole.ToString(), body.GetProperty("yourRole").GetString());
        Assert.Equal(expectedRole, await Factory.RoleInAsync(team.Id, team.Owner.Id));
        Assert.Equal(OrganizationRole.Owner, await Factory.RoleInAsync(team.Id, team.Member.Id));
        Assert.Equal(1, await OwnerCountAsync(team));

        var audit = Assert.Single(await Factory.AuditAsync(AuditAction.OrgOwnershipTransferred));
        Assert.Equal(team.Owner.Id, audit.ActorUserId);
        Assert.Equal(team.Member.Id, audit.TargetUserId);
        Assert.Contains(expectedRole.ToString(), audit.Metadata);
    }

    [Theory]
    [InlineData(Who.Admin, HttpStatusCode.Forbidden)]
    [InlineData(Who.Member, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, HttpStatusCode.NotFound)]
    public async Task Only_the_owner_can_hand_the_organization_over(Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();
        var successor = who == Who.Member ? team.Admin : team.Member;

        var response = await TransferAsync(team.As(who), team, successor.Id);

        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(OrganizationRole.Owner, await Factory.RoleInAsync(team.Id, team.Owner.Id));
        Assert.Equal(1, await OwnerCountAsync(team));
    }

    [Fact]
    public async Task An_admin_cannot_take_the_organization_by_naming_themselves()
    {
        var team = await Factory.CreateTeamAsync();

        var response = await TransferAsync(team.As(Who.Admin), team, team.Admin.Id);

        Assert.False(response.IsSuccessStatusCode);
        Assert.Equal(OrganizationRole.Admin, await Factory.RoleInAsync(team.Id, team.Admin.Id));
        Assert.Equal(OrganizationRole.Owner, await Factory.RoleInAsync(team.Id, team.Owner.Id));
    }

    [Fact]
    public async Task Handing_the_organization_to_yourself_is_refused()
    {
        var team = await Factory.CreateTeamAsync();

        var response = await TransferAsync(team.As(Who.Owner), team, team.Owner.Id);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("already own", await ErrorAsync(response));
        Assert.Empty(await Factory.AuditAsync(AuditAction.OrgOwnershipTransferred));
    }

    [Fact]
    public async Task A_hand_over_needs_a_person_to_hand_it_to()
    {
        var team = await Factory.CreateTeamAsync();

        var missing = await team.As(Who.Owner).PostAsJsonAsync(team.Url("/transfer-ownership"), new { });
        var outsider = await TransferAsync(team.As(Who.Owner), team, team.Outsider.Id);

        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, outsider.StatusCode);
        Assert.Equal(1, await OwnerCountAsync(team));
        Assert.Null(await Factory.RoleInAsync(team.Id, team.Outsider.Id));
    }

    [Fact]
    public async Task After_a_hand_over_the_new_owner_holds_the_powers_and_the_old_one_does_not()
    {
        var team = await Factory.CreateTeamAsync();
        (await TransferAsync(team.As(Who.Owner), team, team.Member.Id)).EnsureSuccessStatusCode();

        var oldOwnerDeletes = await team.As(Who.Owner).DeleteAsync(team.Url());
        var newOwnerDeletes = await team.As(Who.Member).DeleteAsync(team.Url());

        Assert.Equal(HttpStatusCode.Forbidden, oldOwnerDeletes.StatusCode);
        Assert.Equal(HttpStatusCode.OK, newOwnerDeletes.StatusCode);
    }
}
