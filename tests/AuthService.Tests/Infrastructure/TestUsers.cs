using System.Net.Http.Json;
using AuthService.Data;
using AuthService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Tests.Infrastructure;

/// <summary>A registered account together with the tokens of a sign-in made after its roles were set.</summary>
public sealed record TestAccount(string Email, string Id, TestTokens Tokens);

/// <summary>
/// Accounts, roles and per-actor clients for tests that need more than one person at once. Each
/// actor gets a client of its own, so one test can act as several users without swapping the
/// shared client's authorization header between requests.
/// </summary>
public static class TestUsers
{
    public const string SuperAdmin = "SuperAdmin";
    public const string Admin = "Admin";

    public static async Task<TestTokens> LoginAsync(
        this HttpClient client, string email, string password = TestData.ValidPassword)
    {
        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password });
        response.EnsureSuccessStatusCode();

        return (await response.Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!;
    }

    /// <summary>
    /// Registers an account and, when <paramref name="role"/> is given, grants it and signs in
    /// again: a role reaches the token only when the token is issued.
    /// </summary>
    public static async Task<TestAccount> CreateAccountAsync(
        this AuthServiceFactory factory, string? role = null, string? email = null)
    {
        var client = factory.ClientFor();
        var (address, tokens) = await client.RegisterAsync(email);

        if (role is not null)
        {
            await factory.AddToRoleAsync(address, role);
            tokens = await client.LoginAsync(address);
        }

        return new TestAccount(address, await factory.UserIdAsync(address), tokens);
    }

    public static Task<string> UserIdAsync(this AuthServiceFactory factory, string email) =>
        factory.ReadUserAsync(email, user => user.Id);

    public static async Task AddToRoleAsync(this AuthServiceFactory factory, string email, string role) =>
        await factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByEmailAsync(email) ?? throw new InvalidOperationException($"No user {email}");
            (await users.AddToRoleAsync(user, role)).ThrowIfFailed();
        });

    /// <summary>Reads a value from the stored user, bypassing tracking so it is always current.</summary>
    public static async Task<T> ReadUserAsync<T>(
        this AuthServiceFactory factory, string email, Func<ApplicationUser, T> read)
    {
        T? value = default;

        await factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var user = await context.Users.AsNoTracking()
                .SingleAsync(u => u.NormalizedEmail == email.ToUpperInvariant());
            value = read(user);
        });

        return value!;
    }

    /// <summary>Changes the stored user directly, for states the API has no way to reach.</summary>
    public static async Task UpdateUserAsync(
        this AuthServiceFactory factory, string email, Action<ApplicationUser> change) =>
        await factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByEmailAsync(email) ?? throw new InvalidOperationException($"No user {email}");
            change(user);
            (await users.UpdateAsync(user)).ThrowIfFailed();
        });

    private static void ThrowIfFailed(this IdentityResult result)
    {
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join("; ", result.Errors.Select(e => e.Description)));
    }
}
