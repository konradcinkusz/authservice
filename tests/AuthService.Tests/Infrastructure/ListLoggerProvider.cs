using Microsoft.Extensions.Logging;

namespace AuthService.Tests.Infrastructure;

/// <summary>One line the application wrote to its log, as a reader of the log would see it.</summary>
public sealed record LoggedEntry(string Category, LogLevel Level, string Message);

/// <summary>
/// Keeps everything the whole application logs, for a test that has to see what a request wrote
/// to the log. Add it with <c>ConfigureServices</c>: <c>services.AddSingleton&lt;ILoggerProvider&gt;(provider)</c>.
/// </summary>
public sealed class ListLoggerProvider : ILoggerProvider
{
    private readonly object _gate = new();
    private readonly List<LoggedEntry> _entries = [];

    public IReadOnlyList<LoggedEntry> Entries
    {
        get
        {
            lock (_gate)
                return [.. _entries];
        }
    }

    public ILogger CreateLogger(string categoryName) => new Logger(categoryName, this);

    public void Dispose()
    {
    }

    private sealed class Logger(string category, ListLoggerProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (owner._gate)
                owner._entries.Add(new LoggedEntry(category, logLevel, formatter(state, exception)));
        }
    }
}
