﻿// <auto-generated/>
#nullable enable

using System.Threading;

namespace Datadog.Trace.Telemetry;
internal partial class MetricsTelemetryCollector
{
    public void RecordGaugeStatsBuckets(int value)
    {
        Interlocked.Exchange(ref _buffer.Gauges[0].Value, value);
    }

    public void RecordGaugeInstrumentations(Datadog.Trace.Telemetry.Metrics.MetricTags.InstrumentationComponent tag, int value)
    {
        var index = 1 + (int)tag;
        Interlocked.Exchange(ref _buffer.Gauges[index].Value, value);
    }

    public void RecordGaugeDirectLogQueue(int value)
    {
        Interlocked.Exchange(ref _buffer.Gauges[7].Value, value);
    }

    /// <summary>
    /// Creates the buffer for the <see cref="Datadog.Trace.Telemetry.Metrics.Gauge" /> values.
    /// </summary>
    private static MetricKey[] GetGaugeBuffer()
        => new MetricKey[]
        {
            new(null),
            new(new[] { "component_name:calltarget" }),
            new(new[] { "component_name:calltarget_derived" }),
            new(new[] { "component_name:calltarget_interfaces" }),
            new(new[] { "component_name:iast" }),
            new(new[] { "component_name:iast_derived" }),
            new(new[] { "component_name:iast_aspects" }),
            new(null),
        };

    /// <summary>
    /// Gets an array of metric counts, indexed by integer value of the <see cref="Datadog.Trace.Telemetry.Metrics.Gauge" />.
    /// Each value represents the number of unique entries in the buffer returned by <see cref="GetGaugeBuffer()" />
    /// It is equal to the cardinality of the tag combinations (or 1 if there are no tags)
    /// </summary>
    private static int[] GaugeEntryCounts { get; }
        = new []{ 1, 6, 1, };
}