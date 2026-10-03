using System.Net;
using System.Net.Http.Json;
using System.Text;
using AuthService.DTOs;
using AuthService.Services;
using AuthService.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// With SendGrid behind the invitation email, what the provider says is what the invitation's
/// delivery status says: a message it refuses is Failed, with the pause and the manual resend
/// that go with it, not Sent.
/// </summary>
public class InvitationDeliveryFailureTests : IntegrationTestBase
{
    private HttpStatusCode _providerAnswers = HttpStatusCode.Accepted;

    protected override void ConfigureServices(IServiceCollection services)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SendGrid:ApiKey"] = "SG.test-key",
            ["SendGrid:FromEmail"] = "noreply@example.test"
        }).Build();
        var provider = new StubHttpHandler(_ => new HttpResponseMessage(_providerAnswers)
        {
            Content = new StringContent("""{"errors":[{"message":"sender identity ops@internal.example is not verified"}]}""", Encoding.UTF8, "application/json")
        });

        services.RemoveAll<IEmailService>();
        services.AddSingleton<IEmailService>(new StubbedSendGridEmailService(configuration, provider));
    }

    [Fact]
    public async Task An_invitation_the_provider_refused_is_failed_not_sent_and_goes_out_when_the_provider_accepts_it()
    {
        var team = await Factory.CreateTeamAsync();
        _providerAnswers = HttpStatusCode.Unauthorized;

        var response = await team.As(Who.Owner).PostAsJsonAsync(team.Url("/invite"), new { email = TestData.NewEmail("invitee") });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var invitation = (await response.Content.ReadFromJsonAsync<InvitationDto>(TestData.Json))!;
        Assert.Equal("Failed", invitation.EmailStatus);
        Assert.Equal("The email provider refused the message (HTTP 401).", invitation.LastEmailError);
        Assert.NotNull(invitation.NextRetryAt);
        Assert.DoesNotContain("internal.example", await response.Content.ReadAsStringAsync());

        _providerAnswers = HttpStatusCode.Accepted;
        await Factory.UpdateInvitationAsync(invitation.Id, i => i.NextRetryAt = DateTime.UtcNow.AddSeconds(-1));
        var resent = await team.As(Who.Owner).PostAsync(team.Url($"/invitations/{invitation.Id}/resend"), null);

        Assert.Equal(HttpStatusCode.OK, resent.StatusCode);
        var delivered = (await resent.Content.ReadFromJsonAsync<InvitationDto>(TestData.Json))!;
        Assert.Equal("Sent", delivered.EmailStatus);
        Assert.Equal(2, delivered.EmailAttemptCount);
        Assert.Null(delivered.LastEmailError);
    }
}
