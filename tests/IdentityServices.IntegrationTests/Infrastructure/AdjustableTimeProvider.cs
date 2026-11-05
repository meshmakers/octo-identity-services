namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     The system clock plus an offset a test can move forward (AB#7859). Used as the security-stamp validator's clock
///     so a test can step past the 30-minute revalidation interval without waiting.
/// </summary>
public sealed class AdjustableTimeProvider : TimeProvider
{
    private long _offsetTicks;

    public TimeSpan Offset => TimeSpan.FromTicks(Interlocked.Read(ref _offsetTicks));

    public void Advance(TimeSpan by) => Interlocked.Add(ref _offsetTicks, by.Ticks);

    public void Reset() => Interlocked.Exchange(ref _offsetTicks, 0);

    public override DateTimeOffset GetUtcNow() => System.GetUtcNow() + Offset;
}
