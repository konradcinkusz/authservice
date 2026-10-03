namespace AuthService.Tests.Infrastructure;

/// <summary>Answers outgoing HTTP calls from a function and remembers them, so no test reaches a real provider.</summary>
public sealed class StubHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
{
    private readonly object _gate = new();
    private readonly List<HttpRequestMessage> _requests = [];
    private readonly List<string?> _bodies = [];

    public IReadOnlyList<HttpRequestMessage> Requests
    {
        get
        {
            lock (_gate)
                return [.. _requests];
        }
    }

    /// <summary>What each request carried, read as it arrived: a client disposes the content once the call is over.</summary>
    public IReadOnlyList<string?> Bodies
    {
        get
        {
            lock (_gate)
                return [.. _bodies];
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);

        lock (_gate)
        {
            _requests.Add(request);
            _bodies.Add(body);
        }

        return respond(request);
    }
}

public sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
}
