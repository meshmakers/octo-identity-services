using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>Collects the measurements of <c>octo.rest.deprecated.calls</c> while it lives.</summary>
internal sealed class DeprecatedCallCollector : IDisposable
{
    private readonly MeterListener _listener = new();
    private readonly ConcurrentQueue<DeprecatedCallMeasurement> _measurements = new();

    public DeprecatedCallCollector()
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == "Meshmakers.Octo.RestDeprecation" &&
                instrument.Name == "octo.rest.deprecated.calls")
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            var dictionary = new Dictionary<string, string>();
            foreach (var tag in tags)
            {
                dictionary[tag.Key] = tag.Value?.ToString() ?? string.Empty;
            }

            _measurements.Enqueue(new DeprecatedCallMeasurement(value, dictionary));
        });
        _listener.Start();
    }

    public IReadOnlyList<DeprecatedCallMeasurement> Snapshot() => _measurements.ToArray();

    public void Dispose() => _listener.Dispose();
}

internal sealed record DeprecatedCallMeasurement(long Value, IReadOnlyDictionary<string, string> Tags);
