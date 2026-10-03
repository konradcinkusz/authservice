using AuthService.Extensions;

namespace AuthService.Tests.Infrastructure;

/// <summary>
/// A schema that never arrives, which says when something has begun to wait for it. The host runs a
/// background service on another thread, so a test that stops one straight after starting it may
/// have cancelled it before it ran at all, and have tested nothing.
/// </summary>
public sealed class ParkedSignal : IMigrationCompletionSignal
{
    private readonly TaskCompletionSource _waiting = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Completes when something has started to wait on the signal.</summary>
    public Task Waiting => _waiting.Task;

    public Task WaitAsync(CancellationToken cancellationToken = default)
    {
        _waiting.TrySetResult();

        return Task.Delay(Timeout.Infinite, cancellationToken);
    }

    public void SetCompleted()
    {
    }

    public bool IsCompleted => false;
}
