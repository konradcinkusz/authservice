using Microsoft.Extensions.Logging;

namespace AuthService.Tests.Infrastructure;

/// <summary>Keeps what was logged, formatted as a reader of the log would see it.</summary>
public sealed class ListLogger<T> : ILogger<T>
{
    private readonly object _gate = new();
    private readonly List<string> _messages = [];

    public IReadOnlyList<string> Messages
    {
        get
        {
            lock (_gate)
                return [.. _messages];
        }
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        lock (_gate)
            _messages.Add(formatter(state, exception));
    }
}
