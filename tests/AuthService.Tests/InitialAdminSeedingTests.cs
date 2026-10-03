using System.Net;
using System.Net.Http.Json;
using AuthService.Data;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The first SuperAdmin comes from <c>InitialAdmin:Email</c> and <c>InitialAdmin:Password</c>,
/// and only while no SuperAdmin exists (docs/roles.md). It is the one way an account is given
/// the highest role without another admin doing it, so each branch is pinned.
/// </summary>
public class InitialAdminSeedingTests : IntegrationTestBase
{
    private const string AdminPassword = "Initi4l-Admin-Passw0rd!";

    private static IConfiguration Configure(string? email, string? password) =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["InitialAdmin:Email"] = email,
            ["InitialAdmin:Password"] = password
        }).Build();

    private Task SeedAsync(string? email, string? password) =>
        Factory.WithScopeAsync(services => DbSeeder.SeedInitialAdminAsync(
            services.GetRequiredService<UserManager<ApplicationUser>>(),
            Configure(email, password),
            NullLogger.Instance));

    private async Task<List<string>> SuperAdminEmailsAsync()
    {
        List<string> emails = [];
        await Factory.WithScopeAsync(async services =>
        {
            var admins = await services.GetRequiredService<UserManager<ApplicationUser>>().GetUsersInRoleAsync(TestUsers.SuperAdmin);
            emails = admins.Select(a => a.Email!).ToList();
        });

        return emails;
    }

    private async Task<int> UserCountAsync()
    {
        var count = 0;
        await Factory.WithScopeAsync(async services =>
            count = await services.GetRequiredService<ApplicationDbContext>().Users.CountAsync());

        return count;
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("admin@example.test", null)]
    [InlineData(null, AdminPassword)]
    [InlineData("admin@example.test", "")]
    [InlineData("   ", AdminPassword)]
    public async Task Nothing_is_created_unless_both_the_address_and_the_password_are_set(string? email, string? password)
    {
        await SeedAsync(email, password);

        Assert.Equal(0, await UserCountAsync());
        Assert.Empty(await SuperAdminEmailsAsync());
    }

    [Fact]
    public async Task A_super_admin_is_created_confirmed_and_able_to_sign_in_and_use_the_admin_api()
    {
        await SeedAsync("first.admin+ops@example.test", AdminPassword);

        var admin = Assert.Single(await SuperAdminEmailsAsync());
        Assert.Equal("first.admin+ops@example.test", admin);
        Assert.Equal("firstadminops", await Factory.ReadUserAsync(admin, u => u.UserName));
        Assert.True(await Factory.ReadUserAsync(admin, u => u.EmailConfirmed));

        var tokens = await Factory.ClientFor().LoginAsync(admin, AdminPassword);
        var stats = await Factory.ClientFor(tokens).GetAsync("/api/v1/admin/stats");
        Assert.Equal(HttpStatusCode.OK, stats.StatusCode);
    }

    [Fact]
    public async Task Seeding_again_changes_nothing_even_when_the_configured_address_has_since_changed()
    {
        await SeedAsync("first-admin@example.test", AdminPassword);

        await SeedAsync("first-admin@example.test", AdminPassword);
        await SeedAsync("someone-else@example.test", AdminPassword);

        Assert.Equal(["first-admin@example.test"], await SuperAdminEmailsAsync());
        Assert.Equal(1, await UserCountAsync());
    }

    [Fact]
    public async Task An_existing_account_with_that_address_is_promoted_and_keeps_its_own_password()
    {
        var (email, _) = await Factory.ClientFor().RegisterAsync();

        await SeedAsync(email, AdminPassword);

        Assert.Equal([email], await SuperAdminEmailsAsync());
        Assert.Equal(1, await UserCountAsync());
        var tokens = await Factory.ClientFor().LoginAsync(email);
        Assert.Contains(TestUsers.SuperAdmin, tokens.Roles());
        var withConfiguredPassword = await Factory.ClientFor()
            .PostAsJsonAsync("/api/v1/auth/login", new { email, password = AdminPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, withConfiguredPassword.StatusCode);
    }

    [Fact]
    public async Task A_password_the_policy_refuses_creates_nobody_and_does_not_stop_startup()
    {
        await SeedAsync("weak-admin@example.test", "weak");

        Assert.Equal(0, await UserCountAsync());
        Assert.Empty(await SuperAdminEmailsAsync());
    }

    [Fact]
    public async Task Seeding_the_roles_twice_leaves_exactly_the_default_roles()
    {
        await Factory.WithScopeAsync(async services =>
        {
            await DbSeeder.SeedAsync(services);
            await DbSeeder.SeedAsync(services);

            var roles = services.GetRequiredService<RoleManager<IdentityRole>>().Roles.Select(r => r.Name!).ToList();
            Assert.Equal(DbSeeder.DefaultRoles.Order(), roles.Order());
        });
    }
}

/// <summary>The same thing the way a deployment does it: through configuration, at startup.</summary>
public class InitialAdminFromConfigurationTests : IntegrationTestBase
{
    protected override IReadOnlyDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        ["InitialAdmin:Email"] = "configured-admin@example.test",
        ["InitialAdmin:Password"] = "Configur3d-Admin-Passw0rd!"
    };

    [Fact]
    public async Task The_account_configured_at_startup_is_a_super_admin_who_can_use_the_admin_api()
    {
        var tokens = await Factory.ClientFor().LoginAsync("configured-admin@example.test", "Configur3d-Admin-Passw0rd!");

        var users = await Factory.ClientFor(tokens).GetAsync("/api/v1/admin/users");

        Assert.Equal(HttpStatusCode.OK, users.StatusCode);
    }
}
