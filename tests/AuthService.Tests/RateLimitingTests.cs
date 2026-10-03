using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Tests.Infrastructure;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The limit on the endpoints a password can be guessed at: twenty requests a minute from one
/// address, a short queue after that, and a refusal beyond it.
/// </summary>
public class RateLimitingTests : IntegrationTestBase
{
    private const string Login = "/api/v1/auth/login";

    private static Task<HttpResponseMessage> GuessAsync(HttpClient client, CancellationToken cancellation = default) =>
        client.PostAsJsonAsync(Login, new { email = "nobody@example.test", password = "wrong" }, cancellation);

    [Fact]
    public async Task The_twenty_first_sign_in_request_in_a_minute_is_queued_and_the_one_after_the_queue_is_full_is_refused()
    {
        var client = Factory.ClientFor();
        for (var i = 0; i < 20; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await GuessAsync(client)).StatusCode);

        // The next five wait for the window to reset, so none of them answers in this test; the
        // sixth is refused at once, and it is the only one that can answer.
        using var giveUp = new CancellationTokenSource();
        var burst = Enumerable.Range(0, 6).Select(_ => GuessAsync(client, giveUp.Token)).ToList();
        var refused = await await Task.WhenAny(burst);
        giveUp.Cancel();
        await Task.WhenAll(burst.Select(t => t.ContinueWith(_ => { })));

        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
        var body = await refused.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Contains("Too many requests", body.GetProperty("error").GetString());
        Assert.True(body.TryGetProperty("retryAfter", out _));
    }

    [Fact]
    public async Task Ordinary_api_requests_do_not_draw_on_the_sign_in_limit()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);

        for (var i = 0; i < 30; i++)
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/organizations")).StatusCode);
    }
}
