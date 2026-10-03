using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.DTOs;
using AuthService.Models;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Inviting people into an organization and the other side of it: the email, accepting, the two
/// lists, resending when delivery failed, and taking an invitation back.
/// </summary>
public class OrganizationInvitationTests : IntegrationTestBase
{
    private const string Organizations = "/api/v1/organizations";
    private const string Accept = $"{Organizations}/invitations/accept";

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<T>(TestData.Json))!;

    private static async Task<string> ErrorAsync(HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString()!;

    private static void AssertNear(DateTime? actual, DateTime expected, TimeSpan tolerance)
    {
        Assert.NotNull(actual);
        Assert.InRange(actual.Value, expected - tolerance, expected + tolerance);
    }

    private static Task<HttpResponseMessage> InviteAsync(
        HttpClient client, OrganizationTeam team, string email, string? role = null) =>
        client.PostAsJsonAsync(team.Url("/invite"), role is null ? new { email } : (object)new { email, role });

    /// <summary>Invites an address as the owner and returns the invitation as the API describes it.</summary>
    private static async Task<InvitationDto> InviteAsOwnerAsync(OrganizationTeam team, string email, string? role = null)
    {
        var response = await InviteAsync(team.As(Who.Owner), team, email, role);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return await ReadAsync<InvitationDto>(response);
    }

    private string TokenFor(string email) => Factory.Emails.To(email, EmailKind.Invitation).Last().Token!;

    private static Task<HttpResponseMessage> AcceptAsync(HttpClient client, string token) =>
        client.PostAsJsonAsync(Accept, new { token });

    private static Task<HttpResponseMessage> ResendAsync(HttpClient client, OrganizationTeam team, string invitationId) =>
        client.PostAsync(team.Url($"/invitations/{invitationId}/resend"), null);

    private async Task<OrganizationInvitation> StoredAsync(OrganizationTeam team, string invitationId) =>
        (await Factory.StoredInvitationsAsync(team.Id)).Single(i => i.Id == invitationId);

    private Task ExpireAsync(string invitationId) =>
        Factory.UpdateInvitationAsync(invitationId, i => i.ExpiresAt = DateTime.UtcNow.AddMinutes(-1));

    /// <summary>Makes the last send old enough that the "recently sent" pause no longer applies.</summary>
    private Task AgeLastSendAsync(string invitationId) =>
        Factory.UpdateInvitationAsync(invitationId, i => i.LastEmailAttemptAt = DateTime.UtcNow.AddMinutes(-6));

    /// <summary>Makes the pause that follows a failed send run out.</summary>
    private Task EndWaitAsync(string invitationId) =>
        Factory.UpdateInvitationAsync(invitationId, i => i.NextRetryAt = DateTime.UtcNow.AddSeconds(-1));

    // ─── Inviting ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Owner, HttpStatusCode.OK)]
    [InlineData(Who.Admin, HttpStatusCode.OK)]
    [InlineData(Who.Member, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, HttpStatusCode.Forbidden)]
    public async Task Owners_and_admins_can_invite_and_nobody_else_can(Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");

        var response = await InviteAsync(team.As(who), team, invitee);

        Assert.Equal(expected, response.StatusCode);
        var invited = expected == HttpStatusCode.OK;
        Assert.Equal(invited ? 1 : 0, (await Factory.StoredInvitationsAsync(team.Id)).Count);
        Assert.Equal(invited ? 1 : 0, Factory.Emails.To(invitee, EmailKind.Invitation).Count());
    }

    [Fact]
    public async Task An_invitation_is_recorded_and_emailed_in_the_inviters_name()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");

        var invitation = await InviteAsOwnerAsync(team, invitee, "Admin");

        Assert.Equal(team.Id, invitation.OrganizationId);
        Assert.Equal("Acme", invitation.OrganizationName);
        Assert.Equal(invitee, invitation.Email);
        Assert.Equal("Admin", invitation.Role);
        Assert.False(invitation.IsAccepted);
        Assert.Equal("Sent", invitation.EmailStatus);
        Assert.Equal(1, invitation.EmailAttemptCount);
        Assert.Null(invitation.NextRetryAt);
        Assert.Null(invitation.LastEmailError);
        AssertNear(invitation.ExpiresAt, DateTime.UtcNow.AddDays(7), TimeSpan.FromMinutes(1));

        var email = Assert.Single(Factory.Emails.To(invitee, EmailKind.Invitation));
        Assert.Equal("Acme", email.Detail);
        Assert.Equal(await Factory.ReadUserAsync(team.Owner.Email, u => u.UserName), email.Inviter);

        var stored = await StoredAsync(team, invitation.Id);
        Assert.Equal(email.Token, stored.Token);
        Assert.Equal(team.Owner.Id, stored.InvitedByUserId);
        var attempt = Assert.Single(stored.EmailAttempts);
        Assert.True(attempt.IsSuccessful);
        Assert.Equal(1, attempt.AttemptNumber);

        var audit = Assert.Single(await Factory.AuditAsync(AuditAction.OrgMemberInvited));
        Assert.Equal(team.Owner.Id, audit.ActorUserId);
        Assert.Equal(team.Id, audit.TargetOrganizationId);
        Assert.Contains(invitee, audit.Metadata);
        Assert.Contains("Admin", audit.Metadata);
    }

    [Fact]
    public async Task The_token_in_the_link_is_256_bits_of_url_safe_randomness_and_different_every_time()
    {
        var team = await Factory.CreateTeamAsync();
        var first = TestData.NewEmail("first");
        var second = TestData.NewEmail("second");

        await InviteAsOwnerAsync(team, first);
        await InviteAsOwnerAsync(team, second);

        Assert.Matches("^[A-Za-z0-9_-]{43}$", TokenFor(first));
        Assert.NotEqual(TokenFor(first), TokenFor(second));
    }

    [Theory]
    [InlineData(null, "Member")]
    [InlineData("Member", "Member")]
    [InlineData("Admin", "Admin")]
    [InlineData("Owner", "Owner")]
    public async Task The_invitation_carries_the_role_it_was_sent_with_and_member_when_none_was_named(
        string? asked, string expected)
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");

        var invitation = await InviteAsOwnerAsync(team, invitee, asked);

        Assert.Equal(expected, invitation.Role);
        Assert.Equal(Enum.Parse<OrganizationRole>(expected), (await StoredAsync(team, invitation.Id)).Role);
    }

    [Fact]
    public async Task The_audit_row_names_the_invited_account_when_there_is_one()
    {
        var team = await Factory.CreateTeamAsync();
        var existing = await Factory.CreateAccountAsync();

        await InviteAsOwnerAsync(team, existing.Email);
        await InviteAsOwnerAsync(team, TestData.NewEmail("nobody-yet"));

        var rows = await Factory.AuditAsync(AuditAction.OrgMemberInvited);
        Assert.Equal(2, rows.Count);
        Assert.Equal(existing.Id, rows[0].TargetUserId);
        Assert.Null(rows[1].TargetUserId);
    }

    [Fact]
    public async Task Someone_who_is_already_a_member_cannot_be_invited_whatever_the_case_of_their_address()
    {
        var team = await Factory.CreateTeamAsync();

        var exact = await InviteAsync(team.As(Who.Owner), team, team.Member.Email);
        var shouted = await InviteAsync(team.As(Who.Owner), team, team.Member.Email.ToUpperInvariant());

        Assert.Equal(HttpStatusCode.BadRequest, exact.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, shouted.StatusCode);
        Assert.Contains("already a member", await ErrorAsync(exact));
        Assert.Empty(await Factory.StoredInvitationsAsync(team.Id));
        Assert.Empty(Factory.Emails.To(team.Member.Email, EmailKind.Invitation));
    }

    [Fact]
    public async Task A_second_invitation_to_an_address_with_one_pending_is_refused()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");
        await InviteAsOwnerAsync(team, invitee);

        var again = await InviteAsync(team.As(Who.Admin), team, invitee);

        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
        Assert.Contains("already been sent", await ErrorAsync(again));
        Assert.Single(await Factory.StoredInvitationsAsync(team.Id));
        Assert.Single(Factory.Emails.To(invitee, EmailKind.Invitation));
    }

    [Fact]
    public async Task An_invitation_that_has_expired_does_not_stop_a_new_one()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");
        var first = await InviteAsOwnerAsync(team, invitee);
        await ExpireAsync(first.Id);

        var second = await InviteAsOwnerAsync(team, invitee);

        Assert.NotEqual(first.Id, second.Id);
        Assert.Equal(2, (await Factory.StoredInvitationsAsync(team.Id)).Count);
        Assert.Equal(2, Factory.Emails.To(invitee, EmailKind.Invitation).Count());
    }

    [Fact]
    public async Task Someone_who_accepted_and_later_left_can_be_invited_again()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(invitee.Tokens);
        await InviteAsOwnerAsync(team, invitee.Email);
        (await AcceptAsync(client, TokenFor(invitee.Email))).EnsureSuccessStatusCode();
        (await client.DeleteAsync(team.Url("/members/me"))).EnsureSuccessStatusCode();

        var again = await InviteAsync(team.As(Who.Owner), team, invitee.Email);

        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        (await AcceptAsync(client, TokenFor(invitee.Email))).EnsureSuccessStatusCode();
        Assert.Equal(OrganizationRole.Member, await Factory.RoleInAsync(team.Id, invitee.Id));
    }

    public static TheoryData<string, string?> MalformedInvitations => new()
    {
        { "", "Member" },
        { "not-an-email", "Member" },
        { $"{new string('a', 250)}@example.test", "Member" },
        { "invitee@example.test", "Superuser" },
    };

    [Theory]
    [MemberData(nameof(MalformedInvitations))]
    public async Task A_malformed_invitation_is_refused_with_the_reasons(string email, string? role)
    {
        var team = await Factory.CreateTeamAsync();

        var response = await InviteAsync(team.As(Who.Owner), team, email, role);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True((await response.Content.ReadFromJsonAsync<JsonElement>()).TryGetProperty("errors", out _));
        Assert.Empty(await Factory.StoredInvitationsAsync(team.Id));
    }

    [Fact]
    public async Task A_failing_email_provider_leaves_the_invitation_in_place_marked_failed()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");
        Factory.Emails.FailWith = new InvalidOperationException("provider down");

        var invitation = await InviteAsOwnerAsync(team, invitee);

        Assert.Equal("Failed", invitation.EmailStatus);
        Assert.Equal(1, invitation.EmailAttemptCount);
        Assert.Equal("provider down", invitation.LastEmailError);
        AssertNear(invitation.NextRetryAt, DateTime.UtcNow.AddMinutes(10), TimeSpan.FromMinutes(1));
        Assert.Empty(Factory.Emails.To(invitee));

        var attempt = Assert.Single((await StoredAsync(team, invitation.Id)).EmailAttempts);
        Assert.False(attempt.IsSuccessful);
        Assert.Equal("provider down", attempt.ErrorMessage);
        Assert.Contains(nameof(InvalidOperationException), attempt.ErrorDetails);
    }

    // ─── Accepting ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData("Member")]
    [InlineData("Admin")]
    [InlineData("Owner")]
    public async Task Accepting_makes_the_invitee_a_member_with_the_invited_role(string role)
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = await Factory.CreateAccountAsync();
        var invitation = await InviteAsOwnerAsync(team, invitee.Email, role);
        var client = Factory.ClientFor(invitee.Tokens);

        var response = await AcceptAsync(client, TokenFor(invitee.Email));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(team.Id, (await ReadAsync<JsonElement>(response)).GetProperty("organizationId").GetString());
        Assert.Equal(Enum.Parse<OrganizationRole>(role), await Factory.RoleInAsync(team.Id, invitee.Id));

        var stored = await StoredAsync(team, invitation.Id);
        Assert.True(stored.IsAccepted);
        AssertNear(stored.AcceptedAt, DateTime.UtcNow, TimeSpan.FromMinutes(1));

        var audit = Assert.Single(await Factory.AuditAsync(AuditAction.OrgMemberJoined));
        Assert.Equal(invitee.Id, audit.ActorUserId);
        Assert.Equal(invitee.Id, audit.TargetUserId);
        Assert.Equal(team.Id, audit.TargetOrganizationId);
        Assert.Contains("invitation", audit.Metadata);
        Assert.Contains(role, audit.Metadata);

        var organizations = await ReadAsync<List<OrganizationDto>>(await client.GetAsync(Organizations));
        Assert.Equal(role, Assert.Single(organizations).UserRole);
        Assert.Empty(await ReadAsync<List<InvitationDto>>(await client.GetAsync($"{Organizations}/invitations")));

        // The membership reaches a token the next time one is issued.
        var fresh = await Factory.ClientFor().LoginAsync(invitee.Email);
        Assert.Equal(role, fresh.OrganizationRole(team.Id));
    }

    [Fact]
    public async Task An_invitation_can_be_accepted_once()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = await Factory.CreateAccountAsync();
        await InviteAsOwnerAsync(team, invitee.Email);
        var client = Factory.ClientFor(invitee.Tokens);
        await AcceptAsync(client, TokenFor(invitee.Email));

        var again = await AcceptAsync(client, TokenFor(invitee.Email));

        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
        Assert.Contains("already been accepted", await ErrorAsync(again));
        Assert.Single(await Factory.AuditAsync(AuditAction.OrgMemberJoined));
    }

    [Fact]
    public async Task A_token_that_was_never_issued_finds_no_invitation()
    {
        var invitee = await Factory.CreateAccountAsync();

        var response = await AcceptAsync(Factory.ClientFor(invitee.Tokens), "not-a-token");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task An_invitation_can_only_be_accepted_by_the_address_it_names()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = await Factory.CreateAccountAsync();
        var stranger = await Factory.CreateAccountAsync();
        var invitation = await InviteAsOwnerAsync(team, invitee.Email, "Admin");
        var token = TokenFor(invitee.Email);

        var response = await AcceptAsync(Factory.ClientFor(stranger.Tokens), token);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Null(await Factory.RoleInAsync(team.Id, stranger.Id));
        Assert.False((await StoredAsync(team, invitation.Id)).IsAccepted);
        Assert.Equal(HttpStatusCode.OK, (await AcceptAsync(Factory.ClientFor(invitee.Tokens), token)).StatusCode);
    }

    [Fact]
    public async Task An_expired_invitation_cannot_be_accepted()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = await Factory.CreateAccountAsync();
        var invitation = await InviteAsOwnerAsync(team, invitee.Email);
        await ExpireAsync(invitation.Id);

        var response = await AcceptAsync(Factory.ClientFor(invitee.Tokens), TokenFor(invitee.Email));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("expired", await ErrorAsync(response));
        Assert.Null(await Factory.RoleInAsync(team.Id, invitee.Id));
    }

    [Fact]
    public async Task An_invitation_to_a_deleted_organization_cannot_be_accepted()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = await Factory.CreateAccountAsync();
        await InviteAsOwnerAsync(team, invitee.Email);
        (await team.As(Who.Owner).DeleteAsync(team.Url())).EnsureSuccessStatusCode();

        var response = await AcceptAsync(Factory.ClientFor(invitee.Tokens), TokenFor(invitee.Email));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Null(await Factory.RoleInAsync(team.Id, invitee.Id));
    }

    [Fact]
    public async Task Accepting_when_already_a_member_changes_no_role_and_closes_the_invitation()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = await Factory.CreateAccountAsync();
        var invitation = await InviteAsOwnerAsync(team, invitee.Email);

        // They became an owner some other way before getting round to the email.
        await Factory.AddMemberAsync(team.Id, invitee.Id, OrganizationRole.Owner);
        var response = await AcceptAsync(Factory.ClientFor(invitee.Tokens), TokenFor(invitee.Email));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(OrganizationRole.Owner, await Factory.RoleInAsync(team.Id, invitee.Id));
        Assert.True((await StoredAsync(team, invitation.Id)).IsAccepted);
        Assert.Empty(await Factory.AuditAsync(AuditAction.OrgMemberJoined));
    }

    [Theory]
    [InlineData("")]
    [InlineData("0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789X")]
    public async Task A_blank_or_oversized_token_is_a_bad_request(string token)
    {
        var invitee = await Factory.CreateAccountAsync();

        var response = await AcceptAsync(Factory.ClientFor(invitee.Tokens), token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ─── The two lists ───────────────────────────────────────────────────────

    [Fact]
    public async Task A_person_sees_only_their_own_invitations_that_are_still_open()
    {
        var owner = await Factory.CreateAccountAsync();
        var ownerClient = Factory.ClientFor(owner.Tokens);
        var invitee = await Factory.CreateAccountAsync();
        var other = await Factory.CreateAccountAsync();

        async Task<(string OrganizationId, InvitationDto Invitation)> InviteToNewOrganizationAsync(string name, string email)
        {
            var id = await ownerClient.CreateOrganizationAsync(name);
            var response = await ownerClient.PostAsJsonAsync($"{Organizations}/{id}/invite", new { email });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            return (id, await ReadAsync<InvitationDto>(response));
        }

        await InviteToNewOrganizationAsync("Open", invitee.Email);
        var expired = await InviteToNewOrganizationAsync("Expired", invitee.Email);
        await ExpireAsync(expired.Invitation.Id);
        await InviteToNewOrganizationAsync("Accepted", invitee.Email);
        (await AcceptAsync(Factory.ClientFor(invitee.Tokens),
            Factory.Emails.To(invitee.Email, EmailKind.Invitation).Last().Token!)).EnsureSuccessStatusCode();
        await InviteToNewOrganizationAsync("Someone else's", other.Email);

        var mine = await ReadAsync<List<InvitationDto>>(
            await Factory.ClientFor(invitee.Tokens).GetAsync($"{Organizations}/invitations"));
        var theirs = await ReadAsync<List<InvitationDto>>(
            await Factory.ClientFor(other.Tokens).GetAsync($"{Organizations}/invitations"));

        var open = Assert.Single(mine);
        Assert.Equal("Open", open.OrganizationName);
        Assert.Equal(invitee.Email, open.Email);
        Assert.Equal("Someone else's", Assert.Single(theirs).OrganizationName);
    }

    [Theory]
    [InlineData(Who.Owner, HttpStatusCode.OK)]
    [InlineData(Who.Admin, HttpStatusCode.OK)]
    [InlineData(Who.Member, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, HttpStatusCode.Forbidden)]
    public async Task Owners_and_admins_can_list_the_organizations_invitations_and_nobody_else_can(
        Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();
        await InviteAsOwnerAsync(team, TestData.NewEmail("invitee"));

        var response = await team.As(who).GetAsync(team.Url("/invitations"));

        Assert.Equal(expected, response.StatusCode);
    }

    [Fact]
    public async Task The_organizations_list_holds_open_invitations_newest_first_with_their_delivery_state()
    {
        var team = await Factory.CreateTeamAsync();
        var delivered = await InviteAsOwnerAsync(team, TestData.NewEmail("delivered"));
        Factory.Emails.FailWith = new InvalidOperationException("provider down");
        var failed = await InviteAsOwnerAsync(team, TestData.NewEmail("failed"));
        Factory.Emails.FailWith = null;
        var accepted = await InviteAsOwnerAsync(team, TestData.NewEmail("accepted"));
        await Factory.UpdateInvitationAsync(accepted.Id, i => i.IsAccepted = true);
        var expired = await InviteAsOwnerAsync(team, TestData.NewEmail("expired"));
        await ExpireAsync(expired.Id);

        var listed = await ReadAsync<List<InvitationDto>>(await team.As(Who.Admin).GetAsync(team.Url("/invitations")));

        Assert.Equal([failed.Id, delivered.Id], listed.Select(i => i.Id));
        Assert.Equal(["Failed", "Sent"], listed.Select(i => i.EmailStatus));
        Assert.Equal("provider down", listed[0].LastEmailError);
        Assert.NotNull(listed[0].NextRetryAt);
    }

    // ─── Resending ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Owner, HttpStatusCode.OK)]
    [InlineData(Who.Admin, HttpStatusCode.OK)]
    [InlineData(Who.Member, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, HttpStatusCode.Forbidden)]
    public async Task Owners_and_admins_can_resend_an_invitation_and_nobody_else_can(Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");
        var invitation = await InviteAsOwnerAsync(team, invitee);
        await AgeLastSendAsync(invitation.Id);

        var response = await ResendAsync(team.As(who), team, invitation.Id);

        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(expected == HttpStatusCode.OK ? 2 : 1, Factory.Emails.To(invitee, EmailKind.Invitation).Count());
    }

    [Fact]
    public async Task A_resend_straight_after_a_successful_send_is_refused()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");
        var invitation = await InviteAsOwnerAsync(team, invitee);

        var response = await ResendAsync(team.As(Who.Owner), team, invitation.Id);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("recently sent", await ErrorAsync(response));
        Assert.Single(Factory.Emails.To(invitee, EmailKind.Invitation));
    }

    [Fact]
    public async Task A_resend_after_the_pause_sends_the_same_link_again_and_counts_the_attempt()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");
        var invitation = await InviteAsOwnerAsync(team, invitee);
        await AgeLastSendAsync(invitation.Id);

        var response = await ResendAsync(team.As(Who.Owner), team, invitation.Id);

        var resent = await ReadAsync<InvitationDto>(response);
        Assert.Equal("Sent", resent.EmailStatus);
        Assert.Equal(2, resent.EmailAttemptCount);
        AssertNear(resent.LastEmailAttemptAt, DateTime.UtcNow, TimeSpan.FromMinutes(1));
        var sent = Factory.Emails.To(invitee, EmailKind.Invitation).ToList();
        Assert.Equal(2, sent.Count);
        Assert.Equal(sent[0].Token, sent[1].Token);
        Assert.Equal(2, (await StoredAsync(team, invitation.Id)).EmailAttempts.Count);
    }

    [Fact]
    public async Task The_wait_after_a_failed_send_grows_with_each_failure_up_to_a_day()
    {
        var team = await Factory.CreateTeamAsync();
        Factory.Emails.FailWith = new InvalidOperationException("provider down");
        var invitation = await InviteAsOwnerAsync(team, TestData.NewEmail("invitee"));

        var waits = new List<TimeSpan>();
        async Task NoteWaitAsync()
        {
            var stored = await StoredAsync(team, invitation.Id);
            waits.Add(stored.NextRetryAt!.Value - stored.LastEmailAttemptAt!.Value);
        }

        await NoteWaitAsync();
        for (var attempt = 2; attempt <= 4; attempt++)
        {
            await EndWaitAsync(invitation.Id);
            var response = await ResendAsync(team.As(Who.Owner), team, invitation.Id);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("provider down", await ErrorAsync(response));
            await NoteWaitAsync();
        }

        TimeSpan[] expected = [TimeSpan.FromMinutes(10), TimeSpan.FromHours(1), TimeSpan.FromHours(24), TimeSpan.FromHours(24)];
        for (var i = 0; i < expected.Length; i++)
            Assert.InRange(waits[i], expected[i] - TimeSpan.FromSeconds(1), expected[i] + TimeSpan.FromSeconds(5));
        var stored = await StoredAsync(team, invitation.Id);
        Assert.Equal(4, stored.EmailAttemptCount);
        Assert.Equal(4, stored.EmailAttempts.Count);
        Assert.All(stored.EmailAttempts, a => Assert.False(a.IsSuccessful));
    }

    [Fact]
    public async Task A_resend_during_the_wait_after_a_failure_is_refused_and_says_how_long()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");
        Factory.Emails.FailWith = new InvalidOperationException("provider down");
        var invitation = await InviteAsOwnerAsync(team, invitee);
        Factory.Emails.FailWith = null;

        var inMinutes = await ResendAsync(team.As(Who.Owner), team, invitation.Id);
        await Factory.UpdateInvitationAsync(invitation.Id, i => i.NextRetryAt = DateTime.UtcNow.AddHours(3).AddMinutes(30));
        var inHours = await ResendAsync(team.As(Who.Owner), team, invitation.Id);

        Assert.Equal(HttpStatusCode.BadRequest, inMinutes.StatusCode);
        Assert.Matches(@"Too many recent attempts\. Please wait \d+ minute\(s\) before resending\.", await ErrorAsync(inMinutes));
        Assert.Equal(HttpStatusCode.BadRequest, inHours.StatusCode);
        Assert.Contains("Please wait 3 hour(s) before resending", await ErrorAsync(inHours));
        Assert.Empty(Factory.Emails.To(invitee));
    }

    [Fact]
    public async Task A_resend_goes_through_once_the_wait_is_over_and_the_provider_is_back()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");
        Factory.Emails.FailWith = new InvalidOperationException("provider down");
        var invitation = await InviteAsOwnerAsync(team, invitee);
        Factory.Emails.FailWith = null;
        await EndWaitAsync(invitation.Id);

        var response = await ResendAsync(team.As(Who.Owner), team, invitation.Id);

        var resent = await ReadAsync<InvitationDto>(response);
        Assert.Equal("Sent", resent.EmailStatus);
        Assert.Equal(2, resent.EmailAttemptCount);
        Assert.Null(resent.LastEmailError);
        Assert.Null(resent.NextRetryAt);
        Assert.Equal((await StoredAsync(team, invitation.Id)).Token, Assert.Single(Factory.Emails.To(invitee)).Token);
    }

    [Theory]
    [InlineData("accepted", "already been accepted")]
    [InlineData("expired", "expired")]
    public async Task An_invitation_that_is_accepted_or_expired_cannot_be_resent(string state, string expectedError)
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = TestData.NewEmail("invitee");
        var invitation = await InviteAsOwnerAsync(team, invitee);
        await Factory.UpdateInvitationAsync(invitation.Id, i =>
        {
            i.LastEmailAttemptAt = DateTime.UtcNow.AddMinutes(-6);
            if (state == "accepted")
                i.IsAccepted = true;
            else
                i.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        });

        var response = await ResendAsync(team.As(Who.Owner), team, invitation.Id);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(expectedError, await ErrorAsync(response));
        Assert.Single(Factory.Emails.To(invitee, EmailKind.Invitation));
    }

    [Fact]
    public async Task Resending_an_invitation_that_is_not_the_organizations_finds_nothing()
    {
        var team = await Factory.CreateTeamAsync();
        var elsewhere = await team.As(Who.Owner).CreateOrganizationAsync("Elsewhere");
        var otherInvitation = await ReadAsync<InvitationDto>(await team.As(Who.Owner)
            .PostAsJsonAsync($"{Organizations}/{elsewhere}/invite", new { email = TestData.NewEmail("invitee") }));
        await AgeLastSendAsync(otherInvitation.Id);

        var unknown = await ResendAsync(team.As(Who.Owner), team, "no-such-invitation");
        var wrongOrganization = await ResendAsync(team.As(Who.Owner), team, otherInvitation.Id);

        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, wrongOrganization.StatusCode);
        Assert.Single(Factory.Emails.To(otherInvitation.Email, EmailKind.Invitation));
    }

    // ─── Taking one back ─────────────────────────────────────────────────────

    [Theory]
    [InlineData(Who.Owner, HttpStatusCode.OK)]
    [InlineData(Who.Admin, HttpStatusCode.OK)]
    [InlineData(Who.Member, HttpStatusCode.Forbidden)]
    [InlineData(Who.Outsider, HttpStatusCode.Forbidden)]
    public async Task Owners_and_admins_can_revoke_an_invitation_and_nobody_else_can(Who who, HttpStatusCode expected)
    {
        var team = await Factory.CreateTeamAsync();
        var invitation = await InviteAsOwnerAsync(team, TestData.NewEmail("invitee"));

        var response = await team.As(who).DeleteAsync(team.Url($"/invitations/{invitation.Id}"));

        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(expected == HttpStatusCode.OK ? 0 : 1, (await Factory.StoredInvitationsAsync(team.Id)).Count);
    }

    [Fact]
    public async Task A_revoked_invitation_cannot_be_accepted_and_its_address_can_be_invited_again()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = await Factory.CreateAccountAsync();
        var invitation = await InviteAsOwnerAsync(team, invitee.Email);
        var revokedToken = TokenFor(invitee.Email);
        (await team.As(Who.Owner).DeleteAsync(team.Url($"/invitations/{invitation.Id}"))).EnsureSuccessStatusCode();

        var accepted = await AcceptAsync(Factory.ClientFor(invitee.Tokens), revokedToken);
        var again = await InviteAsync(team.As(Who.Owner), team, invitee.Email);

        Assert.Equal(HttpStatusCode.NotFound, accepted.StatusCode);
        Assert.Null(await Factory.RoleInAsync(team.Id, invitee.Id));
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.NotEqual(revokedToken, TokenFor(invitee.Email));
    }

    [Fact]
    public async Task An_accepted_invitation_cannot_be_revoked()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = await Factory.CreateAccountAsync();
        var invitation = await InviteAsOwnerAsync(team, invitee.Email);
        (await AcceptAsync(Factory.ClientFor(invitee.Tokens), TokenFor(invitee.Email))).EnsureSuccessStatusCode();

        var response = await team.As(Who.Owner).DeleteAsync(team.Url($"/invitations/{invitation.Id}"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("already been accepted", await ErrorAsync(response));
        Assert.Single(await Factory.StoredInvitationsAsync(team.Id));
        Assert.Equal(OrganizationRole.Member, await Factory.RoleInAsync(team.Id, invitee.Id));
    }

    [Fact]
    public async Task Revoking_an_invitation_that_is_not_the_organizations_finds_nothing()
    {
        var team = await Factory.CreateTeamAsync();
        var elsewhere = await team.As(Who.Owner).CreateOrganizationAsync("Elsewhere");
        var otherInvitation = await ReadAsync<InvitationDto>(await team.As(Who.Owner)
            .PostAsJsonAsync($"{Organizations}/{elsewhere}/invite", new { email = TestData.NewEmail("invitee") }));

        var unknown = await team.As(Who.Owner).DeleteAsync(team.Url("/invitations/no-such-invitation"));
        var wrongOrganization = await team.As(Who.Owner).DeleteAsync(team.Url($"/invitations/{otherInvitation.Id}"));

        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, wrongOrganization.StatusCode);
        Assert.Single(await Factory.StoredInvitationsAsync(elsewhere));
    }
}

/// <summary>
/// Invitations are matched on the address, so an address nobody has proved they hold must not be
/// enough to join. The rule applies wherever verification is on.
/// </summary>
public class OrganizationInvitationEmailGateTests : IntegrationTestBase
{
    private const string Accept = "/api/v1/organizations/invitations/accept";

    /// <summary>
    /// The setting is read from the options on every request. The accounts a test needs sign in
    /// first, while it is off, and a deployment that can send email has it on from then on.
    /// </summary>
    private void RequireVerifiedAddresses() =>
        Factory.Services.GetRequiredService<IOptions<AuthOptions>>().Value.RequireConfirmedEmail = true;

    private async Task<(OrganizationTeam Team, TestAccount Invitee, string Token)> InvitedAsync()
    {
        var team = await Factory.CreateTeamAsync();
        var invitee = await Factory.CreateAccountAsync();
        (await team.As(Who.Owner).PostAsJsonAsync(team.Url("/invite"), new { email = invitee.Email }))
            .EnsureSuccessStatusCode();
        await Factory.UpdateUserAsync(invitee.Email, u => u.EmailConfirmed = false);

        return (team, invitee, Factory.Emails.To(invitee.Email, EmailKind.Invitation).Last().Token!);
    }

    [Fact]
    public async Task An_unverified_address_cannot_accept_until_it_has_been_verified()
    {
        var (team, invitee, token) = await InvitedAsync();
        RequireVerifiedAddresses();
        var client = Factory.ClientFor(invitee.Tokens);

        var refused = await client.PostAsJsonAsync(Accept, new { token });

        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.True((await refused.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("emailVerificationRequired").GetBoolean());
        Assert.Null(await Factory.RoleInAsync(team.Id, invitee.Id));

        await Factory.UpdateUserAsync(invitee.Email, u => u.EmailConfirmed = true);
        var accepted = await client.PostAsJsonAsync(Accept, new { token });

        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(OrganizationRole.Member, await Factory.RoleInAsync(team.Id, invitee.Id));
    }

    [Fact]
    public async Task A_deployment_that_does_not_ask_for_verification_lets_an_unverified_address_accept()
    {
        var (team, invitee, token) = await InvitedAsync();

        var response = await Factory.ClientFor(invitee.Tokens).PostAsJsonAsync(Accept, new { token });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(OrganizationRole.Member, await Factory.RoleInAsync(team.Id, invitee.Id));
    }
}
