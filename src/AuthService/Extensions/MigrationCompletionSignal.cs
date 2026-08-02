namespace AuthService.Extensions;

/// <summary>
/// Signals background services that database migrations and seeding have completed
/// and it is safe to begin querying the database.
/// </summary>
public interface IMigrationCompletionSignal
{
    /// <summary>Returns a task that completes when migrations and seeding are finished.</summary>
    Task WaitAsync(CancellationToken cancellationToken = default);

    /// <summary>Marks migrations and seeding as complete.</summary>
    void SetCompleted();
}

public sealed class MigrationCompletionSignal : IMigrationCompletionSignal
{
    private readonly TaskCompletionSource _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task WaitAsync(CancellationToken cancellationToken = default)
        => cancellationToken.CanBeCanceled
            ? Task.WhenAny(_tcs.Task, Task.Delay(Timeout.Infinite, cancellationToken))
                  .ContinueWith(t => cancellationToken.ThrowIfCancellationRequested(), cancellationToken)
            : _tcs.Task;

    public void SetCompleted() => _tcs.TrySetResult();
}
