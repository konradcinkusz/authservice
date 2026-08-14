using System.Net;
using System.Net.Http.Json;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Refresh-token rotation, storage, replay detection, and the eligibility re-checks that the
/// refresh path previously skipped entirely.
/// </summary>
public class RefreshTokenTests : IntegrationTestBase
{
    private async Task<TestTokens> RefreshAsync(string refreshToken)
    {
        var response = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TestTokens>(TestData.Json))!;
    }

    [Fact]
    public async Task Refresh_rotates_the_token_and_retires_the_old_one()
    {
        var (_, tokens) = await Client.RegisterAsync();

        var rotated = await RefreshAsync(tokens.RefreshToken);

        Assert.NotEqual(tokens.RefreshToken, rotated.RefreshToken);

        // The rotated-away token is dead.
        var replay = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Replaying_a_rotated_token_kills_the_whole_family()
    {
        var (_, tokens) = await Client.RegisterAsync();

        var rotated = await RefreshAsync(tokens.RefreshToken);

        // Replay the superseded token: this is what a stolen-then-rotated token looks like.
        var replay = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);

        // The legitimate client's current token is revoked too — the service cannot tell which
        // side of the replay is the thief, so the session ends rather than continuing to serve
        // an attacker.
        var afterReuse = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = rotated.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, afterReuse.StatusCode);
    }

    [Fact]
    public async Task Refresh_tokens_are_never_stored_in_plaintext()
    {
        var (_, tokens) = await Client.RegisterAsync();

        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var stored = await context.RefreshTokens.AsNoTracking().ToListAsync();

            Assert.NotEmpty(stored);
            Assert.DoesNotContain(stored, t => t.TokenHash == tokens.RefreshToken);
            Assert.Contains(stored, t => t.TokenHash == TokenHasher.Hash(tokens.RefreshToken));
        });
    }

    [Fact]
    public async Task Refresh_is_refused_once_the_account_is_locked_out()
    {
        var (email, tokens) = await Client.RegisterAsync();

        await Factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            await userManager.SetLockoutEndDateAsync(user!, DateTimeOffset.UtcNow.AddMinutes(30));
        });

        var response = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = tokens.RefreshToken });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_is_refused_once_the_account_is_soft_deleted()
    {
        var (email, tokens) = await Client.RegisterAsync();

        await Factory.WithScopeAsync(async services =>
        {
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email);
            user!.IsDeleted = true;
            user.DeletedAt = DateTime.UtcNow;
            await userManager.UpdateAsync(user);
        });

        var response = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = tokens.RefreshToken });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_unknown_refresh_token_is_rejected()
    {
        var response = await Client.PostAsJsonAsync("/api/v1/auth/refresh", new
        {
            refreshToken = Convert.ToBase64String(new byte[64])
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
