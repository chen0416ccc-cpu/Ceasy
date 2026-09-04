internal sealed class WorkflowTestTimeProvider : TimeProvider
{
    private long _utcTicks;

    internal WorkflowTestTimeProvider(DateTimeOffset initialUtc)
    {
        SetUtcNow(initialUtc);
    }

    public override DateTimeOffset GetUtcNow() =>
        new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);

    internal void SetUtcNow(DateTimeOffset value)
    {
        if (value == default)
        {
            throw new ArgumentException("A test UTC time is required.", nameof(value));
        }

        Interlocked.Exchange(ref _utcTicks, value.ToUniversalTime().Ticks);
    }

    internal void Advance(TimeSpan elapsed)
    {
        if (elapsed < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(elapsed));
        }

        Interlocked.Add(ref _utcTicks, elapsed.Ticks);
    }
}
