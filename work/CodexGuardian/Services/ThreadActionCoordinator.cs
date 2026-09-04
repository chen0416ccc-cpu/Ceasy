namespace CodexGuardian.Services;

internal sealed class ThreadActionCoordinator
{
    private readonly SemaphoreSlim[] _leases = Enumerable.Range(0, 64)
        .Select(static _ => new SemaphoreSlim(1, 1))
        .ToArray();

    internal async ValueTask<ThreadActionLease> AcquireAsync(
        string threadId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(threadId);
        var lease = _leases[
            (int)((uint)StringComparer.OrdinalIgnoreCase.GetHashCode(threadId) % _leases.Length)];
        await lease.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new ThreadActionLease(lease);
    }
}

internal sealed class ThreadActionLease : IAsyncDisposable
{
    private SemaphoreSlim? _lease;

    internal ThreadActionLease(SemaphoreSlim lease)
    {
        _lease = lease ?? throw new ArgumentNullException(nameof(lease));
    }

    public ValueTask DisposeAsync()
    {
        Interlocked.Exchange(ref _lease, null)?.Release();
        return ValueTask.CompletedTask;
    }
}
