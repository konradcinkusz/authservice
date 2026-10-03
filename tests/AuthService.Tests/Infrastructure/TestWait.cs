namespace AuthService.Tests.Infrastructure;

public static class TestWait
{
    /// <summary>
    /// Polls until <paramref name="condition"/> holds, for work that happens on another thread
    /// (a hosted service's first pass). Fails the test instead of hanging when it never does.
    /// </summary>
    public static async Task UntilAsync(Func<Task<bool>> condition, string because, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(15));

        while (!await condition())
        {
            if (DateTime.UtcNow > deadline)
                throw new TimeoutException($"Gave up waiting until {because}.");

            await Task.Delay(50);
        }
    }
}
