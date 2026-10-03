using AuthService.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SendGrid;

namespace AuthService.Tests.Infrastructure;

/// <summary>The real SendGrid email service, with the provider's HTTP API replaced by a handler.</summary>
public sealed class StubbedSendGridEmailService(IConfiguration configuration, HttpMessageHandler handler)
    : SendGridEmailService(configuration, NullLogger<SendGridEmailService>.Instance)
{
    protected override ISendGridClient NewClient(string apiKey) =>
        new SendGridClient(new HttpClient(handler), new SendGridClientOptions { ApiKey = apiKey });
}
