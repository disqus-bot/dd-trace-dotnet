﻿// <auto-generated/>
#nullable enable

using System.Threading;

namespace Datadog.Trace.Telemetry;
internal partial class MetricsTelemetryCollector
{
    public void RecordDistributionInitTime(Datadog.Trace.Telemetry.Metrics.MetricTags.InitializationComponent tag, double value)
    {
        var index = 0 + (int)tag;
        _buffer.Distributions[index].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityEndpointPayloadBytes(Datadog.Trace.Telemetry.Metrics.MetricTags.CIVisibilityEndpoints tag, double value)
    {
        var index = 14 + (int)tag;
        _buffer.Distributions[index].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityEndpointPayloadRequestsMs(Datadog.Trace.Telemetry.Metrics.MetricTags.CIVisibilityEndpoints tag, double value)
    {
        var index = 16 + (int)tag;
        _buffer.Distributions[index].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityEndpointPayloadEventsCount(Datadog.Trace.Telemetry.Metrics.MetricTags.CIVisibilityEndpoints tag, double value)
    {
        var index = 18 + (int)tag;
        _buffer.Distributions[index].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityEndpointEventsSerializationMs(Datadog.Trace.Telemetry.Metrics.MetricTags.CIVisibilityEndpoints tag, double value)
    {
        var index = 20 + (int)tag;
        _buffer.Distributions[index].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityGitCommandMs(Datadog.Trace.Telemetry.Metrics.MetricTags.CIVisibilityCommands tag, double value)
    {
        var index = 22 + (int)tag;
        _buffer.Distributions[index].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityGitRequestsSearchCommitsMs(double value)
    {
        _buffer.Distributions[29].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityGitRequestsObjectsPackMs(double value)
    {
        _buffer.Distributions[30].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityGitRequestsObjectsPackBytes(double value)
    {
        _buffer.Distributions[31].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityGitRequestsObjectsPackFiles(double value)
    {
        _buffer.Distributions[32].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityGitRequestsSettingsMs(double value)
    {
        _buffer.Distributions[33].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityITRSkippableTestsRequestMs(double value)
    {
        _buffer.Distributions[34].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityITRSkippableTestsResponseBytes(double value)
    {
        _buffer.Distributions[35].TryEnqueue(value);
    }

    public void RecordDistributionCIVisibilityCodeCoverageFiles(double value)
    {
        _buffer.Distributions[36].TryEnqueue(value);
    }

    /// <summary>
    /// Creates the buffer for the <see cref="Datadog.Trace.Telemetry.Metrics.Distribution" /> values.
    /// </summary>
    private static AggregatedDistribution[] GetDistributionBuffer()
        => new AggregatedDistribution[]
        {
            // init_time, index = 0
            new(new[] { "component:total" }),
            new(new[] { "component:byref_pinvoke" }),
            new(new[] { "component:calltarget_state_byref_pinvoke" }),
            new(new[] { "component:traceattributes_pinvoke" }),
            new(new[] { "component:managed" }),
            new(new[] { "component:calltarget_defs_pinvoke" }),
            new(new[] { "component:serverless" }),
            new(new[] { "component:calltarget_derived_defs_pinvoke" }),
            new(new[] { "component:calltarget_interface_defs_pinvoke" }),
            new(new[] { "component:discovery_service" }),
            new(new[] { "component:rcm" }),
            new(new[] { "component:dynamic_instrumentation" }),
            new(new[] { "component:tracemethods_pinvoke" }),
            new(new[] { "component:iast" }),
            // endpoint_payload.bytes, index = 14
            new(new[] { "endpoint:test_cycle" }),
            new(new[] { "endpoint:code_coverage" }),
            // endpoint_payload.requests_ms, index = 16
            new(new[] { "endpoint:test_cycle" }),
            new(new[] { "endpoint:code_coverage" }),
            // endpoint_payload.events_count, index = 18
            new(new[] { "endpoint:test_cycle" }),
            new(new[] { "endpoint:code_coverage" }),
            // endpoint_payload.events_serialization_ms, index = 20
            new(new[] { "endpoint:test_cycle" }),
            new(new[] { "endpoint:code_coverage" }),
            // git.command_ms, index = 22
            new(new[] { "command:get_repository" }),
            new(new[] { "command:get_branch" }),
            new(new[] { "command:check_shallow" }),
            new(new[] { "command:unshallow" }),
            new(new[] { "command:get_local_commits" }),
            new(new[] { "command:get_objects" }),
            new(new[] { "command:pack_objects" }),
            // git_requests.search_commits_ms, index = 29
            new(null),
            // git_requests.objects_pack_ms, index = 30
            new(null),
            // git_requests.objects_pack_bytes, index = 31
            new(null),
            // git_requests.objects_pack_files, index = 32
            new(null),
            // git_requests.settings_ms, index = 33
            new(null),
            // itr_skippable_tests.request_ms, index = 34
            new(null),
            // itr_skippable_tests.response_bytes, index = 35
            new(null),
            // code_coverage.files, index = 36
            new(null),
        };

    /// <summary>
    /// Gets an array of metric counts, indexed by integer value of the <see cref="Datadog.Trace.Telemetry.Metrics.Distribution" />.
    /// Each value represents the number of unique entries in the buffer returned by <see cref="GetDistributionBuffer()" />
    /// It is equal to the cardinality of the tag combinations (or 1 if there are no tags)
    /// </summary>
    private static int[] DistributionEntryCounts { get; }
        = new []{ 14, 2, 2, 2, 2, 7, 1, 1, 1, 1, 1, 1, 1, 1, };

    private const int _distributionsLength = 37;
}