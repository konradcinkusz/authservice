using System.Net;
using System.Text.Json;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The email a deployment with SendGrid sends. The provider is a stub that keeps what it was
/// asked to send, so these read the message the way the recipient's mail client would get it.
/// </summary>
public class SendGridEmailServiceTests
{
    private const string Token = "token-value_123";

    private sealed record Message(string To, string FromEmail, string? FromName, string Subject, string Text, string Html, string Authorization);

    private static IConfiguration Configuration(params (string Key, string? Value)[] overrides)
    {
        var settings = new Dictionary<string, string?>
        {
            ["SendGrid:ApiKey"] = "SG.test-key",
            ["SendGrid:FromEmail"] = "noreply@example.test",
            ["SendGrid:FromName"] = "Acme Accounts",
            ["App:Name"] = "Acme"
        };
        foreach (var (key, value) in overrides)
            settings[key] = value;

        return new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
    }

    private static StubHttpHandler Accepting() => new(_ => new HttpResponseMessage(HttpStatusCode.Accepted));

    private static async Task<Message> SendAsync(Func<IEmailService, Task> send, IConfiguration? configuration = null)
    {
        var handler = Accepting();

        await send(new StubbedSendGridEmailService(configuration ?? Configuration(), handler));

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://api.sendgrid.com/v3/mail/send", request.RequestUri!.ToString());
        using var body = JsonDocument.Parse(Assert.Single(handler.Bodies)!);
        var root = body.RootElement;
        var content = root.GetProperty("content").EnumerateArray().ToDictionary(
            c => c.GetProperty("type").GetString()!, c => c.GetProperty("value").GetString()!);

        var personalization = root.GetProperty("personalizations")[0];

        return new Message(
            personalization.GetProperty("to")[0].GetProperty("email").GetString()!,
            root.GetProperty("from").GetProperty("email").GetString()!,
            root.GetProperty("from").TryGetProperty("name", out var name) ? name.GetString() : null,
            personalization.GetProperty("subject").GetString()!,
            content["text/plain"],
            content["text/html"],
            request.Headers.Authorization!.ToString());
    }

    // ─── What each message says ──────────────────────────────────────────────

    [Fact]
    public async Task An_invitation_names_who_invited_you_to_what_and_carries_the_token()
    {
        var message = await SendAsync(e => e.SendInvitationEmailAsync("invitee@example.test", "Acme Inc", Token, "jane"));

        Assert.Equal("invitee@example.test", message.To);
        Assert.Equal("noreply@example.test", message.FromEmail);
        Assert.Equal("Acme Accounts", message.FromName);
        Assert.Equal("Bearer SG.test-key", message.Authorization);
        Assert.Equal("You've been invited to join Acme Inc", message.Subject);
        Assert.Equal($"jane has invited you to join Acme Inc.\n\nYour invitation token: {Token}", message.Text);
        Assert.Contains("<strong>jane</strong> has invited you to join <strong>Acme Inc</strong>", message.Html);
        Assert.Contains($"<code>{Token}</code>", message.Html);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task An_invitation_without_a_name_to_give_comes_from_a_team_member(string? inviter)
    {
        var message = await SendAsync(e => e.SendInvitationEmailAsync("invitee@example.test", "Acme Inc", Token, inviter));

        Assert.StartsWith("A team member has invited you to join Acme Inc.", message.Text);
        Assert.Contains("<strong>A team member</strong>", message.Html);
    }

    [Fact]
    public async Task A_password_reset_carries_the_link_and_the_html_link_is_one_a_mail_client_can_follow()
    {
        const string url = "https://app.example.test/reset-password?token=a%2Bb&email=jane%40example.test";

        var message = await SendAsync(e => e.SendPasswordResetEmailAsync("jane@example.test", Token, url));

        Assert.Equal("Reset your password", message.Subject);
        Assert.Contains(url, message.Text);
        Assert.Contains("href=\"https://app.example.test/reset-password?token=a%2Bb&amp;email=jane%40example.test\"", message.Html);
    }

    [Fact]
    public async Task A_verification_carries_the_link_and_names_the_product()
    {
        const string url = "https://app.example.test/verify-email?token=abc&email=jane%40example.test";

        var message = await SendAsync(e => e.SendEmailVerificationAsync("jane@example.test", Token, url));

        Assert.Equal("Verify your email address for Acme", message.Subject);
        Assert.Contains(url, message.Text);
        Assert.Contains("href=\"https://app.example.test/verify-email?token=abc&amp;email=jane%40example.test\"", message.Html);
        Assert.Contains("<strong>Acme</strong>", message.Html);
    }

    [Fact]
    public async Task A_welcome_greets_by_name()
    {
        var message = await SendAsync(e => e.SendWelcomeEmailAsync("jane@example.test", "jane_example"));

        Assert.Equal("Welcome to Acme!", message.Subject);
        Assert.StartsWith("Hi jane_example,", message.Text);
        Assert.Contains("<strong>jane_example</strong>", message.Html);
    }

    [Fact]
    public async Task A_linked_account_notice_names_the_provider_and_says_what_to_do_if_it_was_not_you()
    {
        var message = await SendAsync(e => e.SendOAuthAccountLinkedEmailAsync("jane@example.test", "Google"));

        Assert.Equal("Your account was linked to Google", message.Subject);
        Assert.Contains("If you did not do this, please contact support immediately.", message.Text);
        Assert.Contains("<strong>Google</strong>", message.Html);
    }

    // ─── What a user typed is text, not markup ───────────────────────────────

    [Fact]
    public async Task An_organization_name_is_text_in_the_html_of_an_invitation_whatever_it_contains()
    {
        const string name = "<a href=\"https://phish.example/login\">Sign in again</a> & Co";

        var message = await SendAsync(e => e.SendInvitationEmailAsync("victim@example.test", name, Token, "mallory"));

        Assert.DoesNotContain("<a href", message.Html);
        Assert.DoesNotContain("phish.example/login\">", message.Html);
        Assert.Contains("&lt;a href=&quot;https://phish.example/login&quot;&gt;Sign in again&lt;/a&gt; &amp; Co", message.Html);
        // The plain-text part has no markup to inject into, so it says exactly what was typed.
        Assert.Contains(name, message.Text);
    }

    [Fact]
    public async Task Whatever_goes_into_the_html_of_any_message_is_encoded()
    {
        const string hostile = "<img src=x onerror=alert(1)>";
        var configuration = Configuration(("App:Name", hostile));

        var invitation = await SendAsync(e => e.SendInvitationEmailAsync("a@example.test", "Acme", Token, hostile), configuration);
        var welcome = await SendAsync(e => e.SendWelcomeEmailAsync("a@example.test", hostile), configuration);
        var linked = await SendAsync(e => e.SendOAuthAccountLinkedEmailAsync("a@example.test", hostile), configuration);
        var verification = await SendAsync(e => e.SendEmailVerificationAsync("a@example.test", Token, "https://x.test/?a=1&b=\"2\""), configuration);

        Assert.All(new[] { invitation, welcome, linked, verification }, message =>
        {
            Assert.DoesNotContain("<img", message.Html);
            Assert.DoesNotContain("onerror=alert(1)>", message.Html);
        });
        Assert.Contains("&lt;img src=x onerror=alert(1)&gt;", invitation.Html);
        Assert.Contains("a=1&amp;b=&quot;2&quot;", verification.Html);
    }

    // ─── A message the provider refuses ──────────────────────────────────────

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task A_message_the_provider_refuses_is_an_error_whichever_message_it_is_and_the_providers_words_stay_out_of_it(
        HttpStatusCode status)
    {
        var handler = new StubHttpHandler(_ => new HttpResponseMessage(status)
        {
            Content = new StringContent("""{"errors":[{"message":"sender identity ops@internal.example is not verified"}]}""")
        });
        IEmailService service = new StubbedSendGridEmailService(Configuration(), handler);
        var sends = new (string Kind, Func<Task> Send)[]
        {
            ("invitation", () => service.SendInvitationEmailAsync("a@example.test", "Acme", Token, "jane")),
            ("reset", () => service.SendPasswordResetEmailAsync("a@example.test", Token, "https://app.example.test/reset")),
            ("verification", () => service.SendEmailVerificationAsync("a@example.test", Token, "https://app.example.test/verify")),
            ("welcome", () => service.SendWelcomeEmailAsync("a@example.test", "jane")),
            ("linked", () => service.SendOAuthAccountLinkedEmailAsync("a@example.test", "Google")),
        };

        foreach (var (kind, send) in sends)
        {
            var failure = await Assert.ThrowsAsync<InvalidOperationException>(send);

            Assert.True(
                failure.Message == $"The email provider refused the message (HTTP {(int)status}).",
                $"{kind}: {failure.Message}");
        }

        Assert.Equal(sends.Length, handler.Requests.Count);
    }

    // ─── Configuration ───────────────────────────────────────────────────────

    [Fact]
    public async Task The_sender_is_named_after_the_product_when_no_name_is_set_and_after_the_account_when_there_is_no_product()
    {
        var named = await SendAsync(e => e.SendWelcomeEmailAsync("a@example.test", "a"), Configuration(("SendGrid:FromName", null)));
        var unnamed = await SendAsync(e => e.SendWelcomeEmailAsync("a@example.test", "a"),
            Configuration(("SendGrid:FromName", null), ("App:Name", null)));

        Assert.Equal("Acme", named.FromName);
        Assert.Equal("your account", unnamed.FromName);
        Assert.Equal("Welcome to your account!", unnamed.Subject);
    }

    [Theory]
    [InlineData("SendGrid:ApiKey")]
    [InlineData("SendGrid:FromEmail")]
    public async Task A_message_cannot_be_sent_without_the_key_or_the_sender_address(string missing)
    {
        var handler = Accepting();
        var service = new StubbedSendGridEmailService(Configuration((missing, null)), handler);

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => service.SendWelcomeEmailAsync("a@example.test", "a"));

        Assert.Contains(missing, failure.Message);
        Assert.Empty(handler.Requests);
    }
}
