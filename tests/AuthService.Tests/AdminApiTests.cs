using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Data;
using AuthService.DTOs;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The platform admin API against the capability table in <c>docs/roles.md</c>: who may call
/// what, what each call changes, and the audit row and session revocation that go with it.
/// </summary>
public class AdminApiTests : IntegrationTestBase
{
    private const string NoSuchUser = "no-such-user";

    private Task<TestAccount> NewUserAsync() => Factory.CreateAccountAsync();
    private Task<TestAccount> NewAdminAsync() => Factory.CreateAccountAsync(TestUsers.Admin);
    private Task<TestAccount> NewSuperAdminAsync() => Factory.CreateAccountAsync(TestUsers.SuperAdmin);

    private async Task<T> GetAsync<T>(HttpClient client, string url)
    {
        var response = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return (await response.Content.ReadFromJsonAsync<T>(TestData.Json))!;
    }

    private static async Task<HttpStatusCode> RefreshAsync(HttpClient anonymous, TestTokens tokens) =>
        (await anonymous.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = tokens.RefreshToken })).StatusCode;

    private async Task<List<AuditEvent>> AuditRowsAsync(string action, string? targetUserId = null)
    {
        List<AuditEvent> rows = [];

        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            rows = await context.AuditEvents.AsNoTracking()
                .Where(a => a.Action == action && (targetUserId == null || a.TargetUserId == targetUserId))
                .ToListAsync();
        });

        return rows;
    }

    // ─── Who may call what ───────────────────────────────────────────────────

    public static TheoryData<string, string> AdminEndpoints => new()
    {
        { "GET", "/api/v1/admin/stats" },
        { "GET", "/api/v1/admin/users" },
        { "GET", $"/api/v1/admin/users/{NoSuchUser}" },
        { "POST", $"/api/v1/admin/users/{NoSuchUser}/lock" },
        { "POST", $"/api/v1/admin/users/{NoSuchUser}/unlock" },
        { "POST", $"/api/v1/admin/users/{NoSuchUser}/revoke-sessions" },
        { "DELETE", $"/api/v1/admin/users/{NoSuchUser}" },
        { "GET", "/api/v1/admin/users/deleted" },
        { "POST", $"/api/v1/admin/users/{NoSuchUser}/restore" },
        { "GET", "/api/v1/admin/audit-events" },
        { "GET", "/api/v1/admin/organizations" },
        { "GET", "/api/v1/admin/organizations/no-such-org/invitations" },
        { "POST", $"/api/v1/admin/users/{NoSuchUser}/roles" },
        { "DELETE", $"/api/v1/admin/users/{NoSuchUser}/roles/Admin" },
    };

    private static HttpRequestMessage Request(string method, string url)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), url);

        if (method == "POST")
            request.Content = JsonContent.Create(new { role = "Admin" });

        return request;
    }

    [Theory]
    [MemberData(nameof(AdminEndpoints))]
    public async Task Every_admin_endpoint_refuses_an_anonymous_caller(string method, string url)
    {
        using var request = Request(method, url);

        var response = await Factory.ClientFor().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(AdminEndpoints))]
    public async Task Every_admin_endpoint_refuses_an_ordinary_user(string method, string url)
    {
        var user = await NewUserAsync();
        using var request = Request(method, url);

        var response = await Factory.ClientFor(user.Tokens).SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task An_admin_cannot_assign_platform_roles()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();

        var response = await Factory.ClientFor(admin.Tokens)
            .PostAsJsonAsync($"/api/v1/admin/users/{target.Id}/roles", new { role = TestUsers.Admin });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(await HasRoleAsync(target.Email, TestUsers.Admin));
    }

    [Fact]
    public async Task An_admin_cannot_remove_platform_roles()
    {
        var admin = await NewAdminAsync();
        var target = await Factory.CreateAccountAsync(TestUsers.Admin);

        var response = await Factory.ClientFor(admin.Tokens)
            .DeleteAsync($"/api/v1/admin/users/{target.Id}/roles/{TestUsers.Admin}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.True(await HasRoleAsync(target.Email, TestUsers.Admin));
    }

    private async Task<bool> HasRoleAsync(string email, string role)
    {
        var has = false;

        await Factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            has = await users.IsInRoleAsync((await users.FindByEmailAsync(email))!, role);
        });

        return has;
    }

    // ─── Role management ─────────────────────────────────────────────────────

    [Fact]
    public async Task A_super_admin_assigns_a_role_and_it_is_audited()
    {
        var superAdmin = await NewSuperAdminAsync();
        var target = await NewUserAsync();

        var response = await Factory.ClientFor(superAdmin.Tokens)
            .PostAsJsonAsync($"/api/v1/admin/users/{target.Id}/roles", new { role = TestUsers.Admin });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await HasRoleAsync(target.Email, TestUsers.Admin));

        var row = Assert.Single(await AuditRowsAsync(AuditAction.AdminRoleAssigned, target.Id));
        Assert.Equal(superAdmin.Id, row.ActorUserId);
        Assert.Equal(superAdmin.Email, row.ActorEmail);
        Assert.Contains(TestUsers.Admin, row.Metadata);
    }

    [Fact]
    public async Task Assigning_a_role_ends_the_targets_sessions_so_it_takes_effect_at_once()
    {
        var superAdmin = await NewSuperAdminAsync();
        var target = await NewUserAsync();
        var anonymous = Factory.ClientFor();

        await Factory.ClientFor(superAdmin.Tokens)
            .PostAsJsonAsync($"/api/v1/admin/users/{target.Id}/roles", new { role = TestUsers.Admin });

        Assert.Equal(HttpStatusCode.Unauthorized, await RefreshAsync(anonymous, target.Tokens));
    }

    [Fact]
    public async Task A_role_the_user_already_has_is_rejected()
    {
        var superAdmin = await NewSuperAdminAsync();
        var target = await Factory.CreateAccountAsync(TestUsers.Admin);

        var response = await Factory.ClientFor(superAdmin.Tokens)
            .PostAsJsonAsync($"/api/v1/admin/users/{target.Id}/roles", new { role = TestUsers.Admin });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(await AuditRowsAsync(AuditAction.AdminRoleAssigned, target.Id));
    }

    [Fact]
    public async Task Assigning_a_role_to_an_unknown_user_is_not_found()
    {
        var superAdmin = await NewSuperAdminAsync();

        var response = await Factory.ClientFor(superAdmin.Tokens)
            .PostAsJsonAsync($"/api/v1/admin/users/{NoSuchUser}/roles", new { role = TestUsers.Admin });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Assigning_a_role_that_does_not_exist_is_a_client_error_not_a_server_error()
    {
        var superAdmin = await NewSuperAdminAsync();
        var target = await NewUserAsync();

        var response = await Factory.ClientFor(superAdmin.Tokens)
            .PostAsJsonAsync($"/api/v1/admin/users/{target.Id}/roles", new { role = "NoSuchRole" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_super_admin_removes_a_role_and_it_is_audited()
    {
        var superAdmin = await NewSuperAdminAsync();
        var target = await Factory.CreateAccountAsync(TestUsers.Admin);

        var response = await Factory.ClientFor(superAdmin.Tokens)
            .DeleteAsync($"/api/v1/admin/users/{target.Id}/roles/{TestUsers.Admin}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(await HasRoleAsync(target.Email, TestUsers.Admin));

        var row = Assert.Single(await AuditRowsAsync(AuditAction.AdminRoleRemoved, target.Id));
        Assert.Equal(superAdmin.Id, row.ActorUserId);
        Assert.Contains(TestUsers.Admin, row.Metadata);
    }

    [Fact]
    public async Task Removing_a_role_ends_the_targets_sessions_so_it_takes_effect_at_once()
    {
        var superAdmin = await NewSuperAdminAsync();
        var target = await Factory.CreateAccountAsync(TestUsers.Admin);

        await Factory.ClientFor(superAdmin.Tokens)
            .DeleteAsync($"/api/v1/admin/users/{target.Id}/roles/{TestUsers.Admin}");

        Assert.Equal(HttpStatusCode.Unauthorized, await RefreshAsync(Factory.ClientFor(), target.Tokens));
    }

    [Fact]
    public async Task A_role_the_user_does_not_have_cannot_be_removed()
    {
        var superAdmin = await NewSuperAdminAsync();
        var target = await NewUserAsync();

        var response = await Factory.ClientFor(superAdmin.Tokens)
            .DeleteAsync($"/api/v1/admin/users/{target.Id}/roles/{TestUsers.Admin}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(await AuditRowsAsync(AuditAction.AdminRoleRemoved, target.Id));
    }

    [Fact]
    public async Task Removing_a_role_from_an_unknown_user_is_not_found()
    {
        var superAdmin = await NewSuperAdminAsync();

        var response = await Factory.ClientFor(superAdmin.Tokens)
            .DeleteAsync($"/api/v1/admin/users/{NoSuchUser}/roles/{TestUsers.Admin}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ─── Statistics ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Stats_count_users_by_age_and_organizations()
    {
        var admin = await NewAdminAsync();
        var lastMonth = await NewUserAsync();
        var lastWeek = await NewUserAsync();
        await Factory.UpdateUserAsync(lastMonth.Email, u => u.CreatedAt = DateTime.UtcNow.AddDays(-20));
        await Factory.UpdateUserAsync(lastWeek.Email, u => u.CreatedAt = DateTime.UtcNow.AddDays(-3));
        var ancient = await NewUserAsync();
        await Factory.UpdateUserAsync(ancient.Email, u => u.CreatedAt = DateTime.UtcNow.AddDays(-90));

        var owner = Factory.ClientFor(lastWeek.Tokens);
        (await owner.PostAsJsonAsync("/api/v1/organizations", new { name = "Acme" })).EnsureSuccessStatusCode();

        var stats = await GetAsync<AdminStatsDto>(Factory.ClientFor(admin.Tokens), "/api/v1/admin/stats");

        Assert.Equal(4, stats.TotalUsers);
        Assert.Equal(2, stats.NewUsersLast7Days); // the admin and lastWeek
        Assert.Equal(3, stats.NewUsersLast30Days); // and lastMonth
        Assert.Equal(1, stats.TotalOrganizations);
    }

    // ─── Listing and detail ──────────────────────────────────────────────────

    [Fact]
    public async Task The_user_list_shows_roles_and_leaves_out_deleted_accounts()
    {
        var admin = await NewAdminAsync();
        var kept = await NewUserAsync();
        var deleted = await NewUserAsync();
        await Factory.UpdateUserAsync(deleted.Email, u => u.IsDeleted = true);

        var list = await GetAsync<AdminUserListResponse>(Factory.ClientFor(admin.Tokens), "/api/v1/admin/users");

        Assert.Equal(2, list.TotalCount);
        Assert.DoesNotContain(list.Users, u => u.Id == deleted.Id);
        Assert.Equal(new[] { TestUsers.Admin }, list.Users.Single(u => u.Id == admin.Id).Roles);
        Assert.Empty(list.Users.Single(u => u.Id == kept.Id).Roles);
    }

    [Fact]
    public async Task The_user_list_is_newest_first()
    {
        var admin = await NewAdminAsync();
        var older = await NewUserAsync();
        var oldest = await NewUserAsync();
        await Factory.UpdateUserAsync(older.Email, u => u.CreatedAt = DateTime.UtcNow.AddDays(-2));
        await Factory.UpdateUserAsync(oldest.Email, u => u.CreatedAt = DateTime.UtcNow.AddDays(-5));

        var list = await GetAsync<AdminUserListResponse>(Factory.ClientFor(admin.Tokens), "/api/v1/admin/users");

        Assert.Equal(new[] { admin.Id, older.Id, oldest.Id }, list.Users.Select(u => u.Id));
    }

    [Fact]
    public async Task The_user_list_pages_and_reports_the_page_count()
    {
        var admin = await NewAdminAsync();
        for (var i = 0; i < 4; i++)
            await NewUserAsync();
        var client = Factory.ClientFor(admin.Tokens);

        var second = await GetAsync<AdminUserListResponse>(client, "/api/v1/admin/users?page=2&pageSize=2");
        var third = await GetAsync<AdminUserListResponse>(client, "/api/v1/admin/users?page=3&pageSize=2");

        Assert.Equal(5, second.TotalCount);
        Assert.Equal(3, second.TotalPages);
        Assert.Equal(2, second.Page);
        Assert.Equal(2, second.Users.Count);
        Assert.Single(third.Users);
        Assert.Empty(second.Users.Select(u => u.Id).Intersect(third.Users.Select(u => u.Id)));
    }

    [Theory]
    [InlineData("page=0&pageSize=20", 1, 20)]
    [InlineData("page=-4&pageSize=20", 1, 20)]
    [InlineData("pageSize=0", 1, 1)]
    [InlineData("pageSize=100000", 1, 100)]
    public async Task The_user_list_clamps_paging_it_is_given(string query, int page, int pageSize)
    {
        var admin = await NewAdminAsync();

        var list = await GetAsync<AdminUserListResponse>(Factory.ClientFor(admin.Tokens), $"/api/v1/admin/users?{query}");

        Assert.Equal(page, list.Page);
        Assert.Equal(pageSize, list.PageSize);
    }

    [Fact]
    public async Task The_user_list_searches_email_and_username_without_regard_to_case()
    {
        var admin = await NewAdminAsync();
        var byEmail = await Factory.CreateAccountAsync(email: $"Findme-{Guid.NewGuid():N}@example.test");
        var byName = await NewUserAsync();
        await Factory.UpdateUserAsync(byName.Email, u => u.UserName = "someone-called-ZEBRA");
        await NewUserAsync();
        var client = Factory.ClientFor(admin.Tokens);

        var emailHit = await GetAsync<AdminUserListResponse>(client, "/api/v1/admin/users?search=FINDME-");
        var nameHit = await GetAsync<AdminUserListResponse>(client, "/api/v1/admin/users?search=zebra");
        var blank = await GetAsync<AdminUserListResponse>(client, "/api/v1/admin/users?search=%20%20");

        Assert.Equal(new[] { byEmail.Id }, emailHit.Users.Select(u => u.Id));
        Assert.Equal(new[] { byName.Id }, nameHit.Users.Select(u => u.Id));
        Assert.Equal(4, blank.TotalCount);
    }

    [Fact]
    public async Task User_detail_shows_roles_organizations_and_lockout_state()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();
        var created = await Factory.ClientFor(target.Tokens).PostAsJsonAsync("/api/v1/organizations", new { name = "Acme" });
        created.EnsureSuccessStatusCode();

        var detail = await GetAsync<AdminUserDetailDto>(Factory.ClientFor(admin.Tokens), $"/api/v1/admin/users/{target.Id}");

        Assert.Equal(target.Email, detail.Email);
        Assert.True(detail.EmailConfirmed);
        Assert.False(detail.IsLockedOut);
        Assert.Null(detail.LockoutEnd);
        Assert.Equal(0, detail.AccessFailedCount);
        var membership = Assert.Single(detail.Organizations);
        Assert.Equal("Acme", membership.OrgName);
        Assert.Equal("Owner", membership.Role);
    }

    [Fact]
    public async Task User_detail_for_an_unknown_user_is_not_found()
    {
        var admin = await NewAdminAsync();

        var response = await Factory.ClientFor(admin.Tokens).GetAsync($"/api/v1/admin/users/{NoSuchUser}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ─── Locking ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Locking_an_account_blocks_sign_in_ends_its_sessions_and_is_audited()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();
        var until = DateTimeOffset.UtcNow.AddHours(2);

        var response = await Factory.ClientFor(admin.Tokens)
            .PostAsJsonAsync($"/api/v1/admin/users/{target.Id}/lock", new { until });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var anonymous = Factory.ClientFor();
        Assert.Equal(HttpStatusCode.Unauthorized, await RefreshAsync(anonymous, target.Tokens));

        var login = await anonymous.PostAsJsonAsync("/api/v1/auth/login", new { email = target.Email, password = TestData.ValidPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        using var body = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.GetProperty("lockedOut").GetBoolean());

        var lockoutEnd = await Factory.ReadUserAsync(target.Email, u => u.LockoutEnd);
        Assert.NotNull(lockoutEnd);
        Assert.InRange(lockoutEnd.Value, until.AddSeconds(-1), until.AddSeconds(1));

        var row = Assert.Single(await AuditRowsAsync(AuditAction.AdminUserLocked, target.Id));
        Assert.Equal(admin.Id, row.ActorUserId);
    }

    [Fact]
    public async Task Locking_without_a_date_locks_indefinitely()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();

        var response = await Factory.ClientFor(admin.Tokens).PostAsync($"/api/v1/admin/users/{target.Id}/lock", content: null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var lockoutEnd = await Factory.ReadUserAsync(target.Email, u => u.LockoutEnd);
        Assert.True(lockoutEnd > DateTimeOffset.UtcNow.AddYears(100));
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Contains("indefinitely", body.RootElement.GetProperty("message").GetString());
    }

    [Fact]
    public async Task Locking_works_for_an_account_that_had_lockout_switched_off()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();
        await Factory.UpdateUserAsync(target.Email, u => u.LockoutEnabled = false);

        var response = await Factory.ClientFor(admin.Tokens).PostAsync($"/api/v1/admin/users/{target.Id}/lock", content: null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await Factory.ReadUserAsync(target.Email, u => u.LockoutEnabled));
        Assert.True(await Factory.ReadUserAsync(target.Email, u => u.LockoutEnd > DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task A_lock_date_in_the_past_is_rejected_and_changes_nothing()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();

        var response = await Factory.ClientFor(admin.Tokens)
            .PostAsJsonAsync($"/api/v1/admin/users/{target.Id}/lock", new { until = DateTimeOffset.UtcNow.AddMinutes(-1) });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(await Factory.ReadUserAsync(target.Email, u => u.LockoutEnd));
        Assert.Empty(await AuditRowsAsync(AuditAction.AdminUserLocked, target.Id));
    }

    [Fact]
    public async Task An_admin_cannot_lock_their_own_account()
    {
        var admin = await NewAdminAsync();

        var response = await Factory.ClientFor(admin.Tokens).PostAsync($"/api/v1/admin/users/{admin.Id}/lock", content: null);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(await Factory.ReadUserAsync(admin.Email, u => u.LockoutEnd));
    }

    [Fact]
    public async Task Locking_an_unknown_user_is_not_found()
    {
        var admin = await NewAdminAsync();

        var response = await Factory.ClientFor(admin.Tokens).PostAsync($"/api/v1/admin/users/{NoSuchUser}/lock", content: null);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Unlocking_restores_sign_in_and_clears_failed_attempts()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();
        var client = Factory.ClientFor(admin.Tokens);
        await client.PostAsync($"/api/v1/admin/users/{target.Id}/lock", content: null);
        await Factory.UpdateUserAsync(target.Email, u => u.AccessFailedCount = 3);

        var response = await client.PostAsync($"/api/v1/admin/users/{target.Id}/unlock", content: null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(0, await Factory.ReadUserAsync(target.Email, u => u.AccessFailedCount));
        Assert.Null(await Factory.ReadUserAsync(target.Email, u => u.LockoutEnd));
        await Factory.ClientFor().LoginAsync(target.Email);
        Assert.Single(await AuditRowsAsync(AuditAction.AdminUserUnlocked, target.Id));
    }

    [Fact]
    public async Task Unlocking_an_unknown_user_is_not_found()
    {
        var admin = await NewAdminAsync();

        var response = await Factory.ClientFor(admin.Tokens).PostAsync($"/api/v1/admin/users/{NoSuchUser}/unlock", content: null);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ─── Sessions ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Revoking_sessions_ends_every_refresh_token_without_locking_the_account()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();
        var second = await Factory.ClientFor().LoginAsync(target.Email);

        var response = await Factory.ClientFor(admin.Tokens)
            .PostAsync($"/api/v1/admin/users/{target.Id}/revoke-sessions", content: null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var anonymous = Factory.ClientFor();
        Assert.Equal(HttpStatusCode.Unauthorized, await RefreshAsync(anonymous, target.Tokens));
        Assert.Equal(HttpStatusCode.Unauthorized, await RefreshAsync(anonymous, second));
        await anonymous.LoginAsync(target.Email);
        Assert.Single(await AuditRowsAsync(AuditAction.AdminUserSessionsRevoked, target.Id));
    }

    [Fact]
    public async Task Revoking_the_sessions_of_an_unknown_user_is_not_found()
    {
        var admin = await NewAdminAsync();

        var response = await Factory.ClientFor(admin.Tokens)
            .PostAsync($"/api/v1/admin/users/{NoSuchUser}/revoke-sessions", content: null);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ─── Deleting and restoring ──────────────────────────────────────────────

    [Fact]
    public async Task Deleting_a_user_schedules_permanent_deletion_and_ends_their_access()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();
        var before = DateTime.UtcNow;

        var response = await Factory.ClientFor(admin.Tokens).DeleteAsync($"/api/v1/admin/users/{target.Id}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await Factory.ReadUserAsync(target.Email, u => u.IsDeleted));
        var scheduled = await Factory.ReadUserAsync(target.Email, u => u.ScheduledPermanentDeletionAt);
        Assert.InRange(scheduled!.Value, before.AddDays(ApplicationUser.DefaultRetentionDays).AddMinutes(-1),
            DateTime.UtcNow.AddDays(ApplicationUser.DefaultRetentionDays).AddMinutes(1));

        var anonymous = Factory.ClientFor();
        Assert.Equal(HttpStatusCode.Unauthorized, await RefreshAsync(anonymous, target.Tokens));
        var login = await anonymous.PostAsJsonAsync("/api/v1/auth/login", new { email = target.Email, password = TestData.ValidPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        Assert.Single(await AuditRowsAsync(AuditAction.AdminUserSoftDeleted, target.Id));
    }

    [Fact]
    public async Task A_deleted_user_leaves_the_user_list_and_appears_in_the_deleted_list()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();
        var client = Factory.ClientFor(admin.Tokens);
        await client.DeleteAsync($"/api/v1/admin/users/{target.Id}");

        var users = await GetAsync<AdminUserListResponse>(client, "/api/v1/admin/users");
        var deleted = await GetAsync<DeletedUserListResponse>(client, "/api/v1/admin/users/deleted");

        Assert.DoesNotContain(users.Users, u => u.Id == target.Id);
        var entry = Assert.Single(deleted.Users);
        Assert.Equal(target.Id, entry.Id);
        Assert.Equal(1, deleted.TotalCount);
        Assert.True(entry.ScheduledPermanentDeletionAt > entry.DeletedAt);
    }

    [Fact]
    public async Task An_admin_cannot_delete_their_own_account_from_the_admin_api()
    {
        var admin = await NewAdminAsync();

        var response = await Factory.ClientFor(admin.Tokens).DeleteAsync($"/api/v1/admin/users/{admin.Id}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await Factory.ReadUserAsync(admin.Email, u => u.IsDeleted));
    }

    [Fact]
    public async Task A_user_cannot_be_deleted_twice()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();
        var client = Factory.ClientFor(admin.Tokens);
        await client.DeleteAsync($"/api/v1/admin/users/{target.Id}");

        var again = await client.DeleteAsync($"/api/v1/admin/users/{target.Id}");

        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
        Assert.Single(await AuditRowsAsync(AuditAction.AdminUserSoftDeleted, target.Id));
    }

    [Fact]
    public async Task Deleting_an_unknown_user_is_not_found()
    {
        var admin = await NewAdminAsync();

        var response = await Factory.ClientFor(admin.Tokens).DeleteAsync($"/api/v1/admin/users/{NoSuchUser}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Restoring_a_deleted_user_cancels_the_deletion_and_allows_sign_in_again()
    {
        var admin = await NewAdminAsync();
        var target = await NewUserAsync();
        var client = Factory.ClientFor(admin.Tokens);
        await client.DeleteAsync($"/api/v1/admin/users/{target.Id}");

        var response = await client.PostAsync($"/api/v1/admin/users/{target.Id}/restore", content: null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(await Factory.ReadUserAsync(target.Email, u => u.IsDeleted));
        Assert.Null(await Factory.ReadUserAsync(target.Email, u => u.DeletedAt));
        Assert.Null(await Factory.ReadUserAsync(target.Email, u => u.ScheduledPermanentDeletionAt));
        await Factory.ClientFor().LoginAsync(target.Email);
        Assert.Single(await AuditRowsAsync(AuditAction.AdminUserRestored, target.Id));
    }

    [Fact]
    public async Task Only_a_deleted_user_can_be_restored()
    {
        var admin = await NewAdminAsync();
        var live = await NewUserAsync();
        var client = Factory.ClientFor(admin.Tokens);

        var liveResponse = await client.PostAsync($"/api/v1/admin/users/{live.Id}/restore", content: null);
        var unknownResponse = await client.PostAsync($"/api/v1/admin/users/{NoSuchUser}/restore", content: null);

        Assert.Equal(HttpStatusCode.NotFound, liveResponse.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknownResponse.StatusCode);
    }

    // ─── Audit log ───────────────────────────────────────────────────────────

    [Fact]
    public async Task The_audit_log_filters_by_action_actor_and_target()
    {
        var admin = await NewAdminAsync();
        var other = await NewAdminAsync();
        var first = await NewUserAsync();
        var second = await NewUserAsync();
        var client = Factory.ClientFor(admin.Tokens);
        await client.PostAsync($"/api/v1/admin/users/{first.Id}/lock", content: null);
        await client.PostAsync($"/api/v1/admin/users/{second.Id}/lock", content: null);
        await client.PostAsync($"/api/v1/admin/users/{first.Id}/unlock", content: null);
        await Factory.ClientFor(other.Tokens).PostAsync($"/api/v1/admin/users/{second.Id}/unlock", content: null);

        var locks = await GetAsync<AuditEventListResponse>(client, $"/api/v1/admin/audit-events?action={AuditAction.AdminUserLocked}");
        var byOther = await GetAsync<AuditEventListResponse>(client, $"/api/v1/admin/audit-events?actorUserId={other.Id}&action={AuditAction.AdminUserUnlocked}");
        var onFirst = await GetAsync<AuditEventListResponse>(client, $"/api/v1/admin/audit-events?targetUserId={first.Id}&actorUserId={admin.Id}");

        Assert.Equal(2, locks.TotalCount);
        Assert.All(locks.Events, e => Assert.Equal(AuditAction.AdminUserLocked, e.Action));
        var unlock = Assert.Single(byOther.Events);
        Assert.Equal(second.Id, unlock.TargetUserId);
        Assert.Equal(2, onFirst.TotalCount);
        Assert.All(onFirst.Events, e => Assert.Equal(first.Id, e.TargetUserId));
    }

    [Fact]
    public async Task The_audit_log_is_newest_first_and_bounded_by_time()
    {
        var admin = await NewAdminAsync();
        var client = Factory.ClientFor(admin.Tokens);
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            context.AuditEvents.AddRange(
                new AuditEvent { Action = "test.old", OccurredAt = DateTime.UtcNow.AddDays(-10) },
                new AuditEvent { Action = "test.middle", OccurredAt = DateTime.UtcNow.AddDays(-5) },
                new AuditEvent { Action = "test.new", OccurredAt = DateTime.UtcNow.AddDays(-1) });
            await context.SaveChangesAsync();
        });
        var from = Uri.EscapeDataString(DateTime.UtcNow.AddDays(-7).ToString("O"));
        var to = Uri.EscapeDataString(DateTime.UtcNow.AddDays(-2).ToString("O"));

        var all = await GetAsync<AuditEventListResponse>(client, "/api/v1/admin/audit-events?action=test.old");
        var window = await GetAsync<AuditEventListResponse>(client, $"/api/v1/admin/audit-events?from={from}&to={to}");
        var ordered = (await GetAsync<AuditEventListResponse>(client, "/api/v1/admin/audit-events")).Events
            .Where(e => e.Action.StartsWith("test.")).Select(e => e.Action);

        Assert.Single(all.Events);
        Assert.Equal(new[] { "test.middle" }, window.Events.Select(e => e.Action));
        Assert.Equal(new[] { "test.new", "test.middle", "test.old" }, ordered);
    }

    [Fact]
    public async Task The_audit_log_filters_by_organization()
    {
        var admin = await NewAdminAsync();
        var owner = await NewUserAsync();
        var created = await Factory.ClientFor(owner.Tokens).PostAsJsonAsync("/api/v1/organizations", new { name = "Acme" });
        var orgId = (await created.Content.ReadFromJsonAsync<JsonElement>(TestData.Json)).GetProperty("id").GetString();
        (await Factory.ClientFor(owner.Tokens).PostAsJsonAsync("/api/v1/organizations", new { name = "Other" })).EnsureSuccessStatusCode();

        var log = await GetAsync<AuditEventListResponse>(Factory.ClientFor(admin.Tokens), $"/api/v1/admin/audit-events?organizationId={orgId}");

        var row = Assert.Single(log.Events);
        Assert.Equal(AuditAction.OrganizationCreated, row.Action);
        Assert.Equal(orgId, row.TargetOrganizationId);
    }

    [Theory]
    [InlineData("pageSize=100000", 200)]
    [InlineData("pageSize=0", 1)]
    [InlineData("page=0", 50)]
    public async Task The_audit_log_clamps_paging_it_is_given(string query, int pageSize)
    {
        var admin = await NewAdminAsync();

        var log = await GetAsync<AuditEventListResponse>(Factory.ClientFor(admin.Tokens), $"/api/v1/admin/audit-events?{query}");

        Assert.Equal(pageSize, log.PageSize);
        Assert.Equal(1, log.Page);
    }

    // ─── Organizations ───────────────────────────────────────────────────────

    [Fact]
    public async Task The_organization_list_includes_deleted_organizations_and_counts_members()
    {
        var admin = await NewAdminAsync();
        var owner = await NewUserAsync();
        var client = Factory.ClientFor(owner.Tokens);
        (await client.PostAsJsonAsync("/api/v1/organizations", new { name = "Live Co" })).EnsureSuccessStatusCode();
        var doomed = await client.PostAsJsonAsync("/api/v1/organizations", new { name = "Doomed Co" });
        var doomedId = (await doomed.Content.ReadFromJsonAsync<JsonElement>(TestData.Json)).GetProperty("id").GetString();
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var organization = await context.Organizations.IgnoreQueryFilters().SingleAsync(o => o.Id == doomedId);
            organization.IsDeleted = true;
            organization.DeletedAt = DateTime.UtcNow;
            await context.SaveChangesAsync();
        });

        var response = await Factory.ClientFor(admin.Tokens).GetAsync("/api/v1/admin/organizations");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(2, body.RootElement.GetProperty("totalCount").GetInt32());
        var organizations = body.RootElement.GetProperty("organizations").EnumerateArray().ToList();
        var doomedEntry = organizations.Single(o => o.GetProperty("name").GetString() == "Doomed Co");
        Assert.True(doomedEntry.GetProperty("isDeleted").GetBoolean());
        Assert.Equal(1, doomedEntry.GetProperty("memberCount").GetInt32());
        Assert.False(organizations.Single(o => o.GetProperty("name").GetString() == "Live Co").GetProperty("isDeleted").GetBoolean());
    }

    [Fact]
    public async Task The_organization_list_searches_by_name_and_clamps_paging()
    {
        var admin = await NewAdminAsync();
        var owner = Factory.ClientFor((await NewUserAsync()).Tokens);
        foreach (var name in new[] { "Alpha Labs", "Beta Labs", "Gamma Works" })
            (await owner.PostAsJsonAsync("/api/v1/organizations", new { name })).EnsureSuccessStatusCode();
        var client = Factory.ClientFor(admin.Tokens);

        var labs = JsonDocument.Parse(await (await client.GetAsync("/api/v1/admin/organizations?search=Labs")).Content.ReadAsStringAsync());
        var clamped = JsonDocument.Parse(await (await client.GetAsync("/api/v1/admin/organizations?page=0&pageSize=100000")).Content.ReadAsStringAsync());

        Assert.Equal(2, labs.RootElement.GetProperty("totalCount").GetInt32());
        Assert.Equal(1, clamped.RootElement.GetProperty("page").GetInt32());
        Assert.Equal(100, clamped.RootElement.GetProperty("pageSize").GetInt32());
    }

    [Fact]
    public async Task An_organizations_invitations_are_listed_for_admins()
    {
        var admin = await NewAdminAsync();
        var owner = Factory.ClientFor((await NewUserAsync()).Tokens);
        var created = await owner.PostAsJsonAsync("/api/v1/organizations", new { name = "Acme" });
        var orgId = (await created.Content.ReadFromJsonAsync<JsonElement>(TestData.Json)).GetProperty("id").GetString();
        var invitee = TestData.NewEmail("invitee");
        (await owner.PostAsJsonAsync($"/api/v1/organizations/{orgId}/invite", new { email = invitee, role = "Member" })).EnsureSuccessStatusCode();

        var response = await Factory.ClientFor(admin.Tokens).GetAsync($"/api/v1/admin/organizations/{orgId}/invitations");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(1, body.RootElement.GetProperty("totalCount").GetInt32());
        var invitation = body.RootElement.GetProperty("invitations")[0];
        Assert.Equal(invitee, invitation.GetProperty("email").GetString());
        Assert.Equal("Member", invitation.GetProperty("role").GetString());
        Assert.False(invitation.GetProperty("isAccepted").GetBoolean());
    }
}
