using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// With no email provider configured, mail is logged instead of sent, and the credentials in
/// it are bearer tokens. They may reach a log in Development and nowhere else: this is the
/// default implementation, so it is what a production deployment that never set SendGrid runs.
/// </summary>
public class NoOpEmailServiceTests
{
    private const string Secret = "s3cret-bearer-token-value";
    private const string Link = "https://app.example.test/reset-password?token=s3cret-bearer-token-value";

    private sealed class Host(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "AuthService";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private static (NoOpEmailService Service, ListLogger<NoOpEmailService> Log) Create(string environment)
    {
        var log = new ListLogger<NoOpEmailService>();

        return (new NoOpEmailService(new Host(environment), log), log);
    }

    private static async Task<string> SendEverythingAsync(NoOpEmailService service, ListLogger<NoOpEmailService> log)
    {
        await service.SendPasswordResetEmailAsync("user@example.test", Secret, Link);
        await service.SendEmailVerificationAsync("user@example.test", Secret, Link);
        await service.SendInvitationEmailAsync("user@example.test", "Acme", Secret, "Jane");

        return string.Join("\n", log.Messages);
    }

    [Fact]
    public async Task In_development_the_tokens_and_links_are_logged_so_a_developer_can_follow_them()
    {
        var (service, log) = Create(Environments.Development);

        var logged = await SendEverythingAsync(service, log);

        Assert.Contains(Secret, logged);
        Assert.Contains(Link, logged);
        Assert.Equal(3, log.Messages.Count);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Testing")]
    public async Task Anywhere_else_the_log_says_what_happened_and_withholds_the_credential(string environment)
    {
        var (service, log) = Create(environment);

        var logged = await SendEverythingAsync(service, log);

        Assert.DoesNotContain(Secret, logged);
        Assert.DoesNotContain("reset-password?token", logged);
        Assert.Contains("withheld", logged);
        Assert.Equal(3, log.Messages.Count);
        Assert.All(log.Messages, message => Assert.Contains("user@example.test", message));
        Assert.Contains(log.Messages, m => m.Contains("Password reset email"));
        Assert.Contains(log.Messages, m => m.Contains("Verification email"));
        Assert.Contains(log.Messages, m => m.Contains("Invitation email") && m.Contains("Acme") && m.Contains("Jane"));
    }

    [Fact]
    public async Task Notices_that_carry_no_credential_are_logged_in_full_wherever_it_runs()
    {
        var (service, log) = Create("Production");

        await service.SendWelcomeEmailAsync("user@example.test", "jane");
        await service.SendOAuthAccountLinkedEmailAsync("user@example.test", "Google");

        Assert.Contains(log.Messages, m => m.Contains("Welcome email") && m.Contains("jane"));
        Assert.Contains(log.Messages, m => m.Contains("OAuth account linked") && m.Contains("Google"));
    }
}
