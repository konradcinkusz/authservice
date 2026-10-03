using AuthService.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SendGrid;

namespace AuthService.Tests.Infrastructure;

/// <summary>The real SendGrid email service, with the provider's HTTP API replaced by a handler.</summary>
public sealed class StubbedSendGridEmailService(IConfiguration configuration, HttpMessageHandler handler)
    : SendGridEmailService(configuration, NullLogger<SendGridEmailService>.Instance), IDisposable
{
    // The handler belongs to the test, which reads what it recorded after the call.
    private readonly HttpClient _http = new(handler, disposeHandler: false);

    protected override ISendGridClient NewClient(string apiKey) =>
        new SendGridClient(_http, new SendGridClientOptions { ApiKey = apiKey });

    public void Dispose() => _http.Dispose();
}
