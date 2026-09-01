using Microsoft.Extensions.Logging;

namespace Shared.TestUtilities.Fakes;

/// <summary>
///     An <see cref="ILogger{TCategoryName}" /> that keeps every rendered message so a test can
///     assert on what was — or, more usefully, what was <b>not</b> — written.
/// </summary>
/// <remarks>
///     Introduced for AB#5061, where "the generated mirror secret never reaches a log sink" is a
///     security property and therefore has to be provable rather than reviewed by eye. Renders the
///     message through the supplied formatter, i.e. exactly what a real sink would receive,
///     including any value that a structured placeholder interpolates.
/// </remarks>
public sealed class CapturingLogger<T> : ILogger<T>
{
    private readonly List<string> _messages = [];
    private readonly Lock _gate = new();

    /// <summary>Every message rendered so far, oldest first.</summary>
    public IReadOnlyList<string> Messages
    {
        get
        {
            lock (_gate)
            {
                return _messages.ToList();
            }
        }
    }

    /// <summary>All captured messages joined, for a single substring assertion.</summary>
    public string AllText => string.Join("\n", Messages);

    public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);

        var rendered = formatter(state, exception);
        if (exception != null)
        {
            rendered = $"{rendered} {exception}";
        }

        lock (_gate)
        {
            _messages.Add($"[{logLevel}] {rendered}");
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();
        public void Dispose() { }
    }
}
