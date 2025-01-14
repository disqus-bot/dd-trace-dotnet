﻿// <copyright file="MetricsTelemetryCollectorTests.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace.Telemetry;
using Datadog.Trace.Telemetry.Metrics;
using FluentAssertions;
using FluentAssertions.Execution;
using Xunit;
using NS = Datadog.Trace.Telemetry.MetricNamespaceConstants;

namespace Datadog.Trace.Tests.Telemetry.Collectors;

public class MetricsTelemetryCollectorTests
{
    [Fact]
    public void AggregatingMultipleTimes_GivesNoStats()
    {
        var collector = new MetricsTelemetryCollector(Timeout.InfiniteTimeSpan);
        collector.AggregateMetrics();
        collector.AggregateMetrics();
        collector.AggregateMetrics();
        var metrics = collector.GetMetrics();
        metrics.Metrics.Should().BeNull();
        metrics.Distributions.Should().BeNull();
    }

    [Fact]
    public async Task WithoutAggregation_HasNoStats()
    {
        var collector = new MetricsTelemetryCollector(Timeout.InfiniteTimeSpan);
        collector.Record(PublicApiUsage.Tracer_Configure);
        await Task.Delay(TimeSpan.FromSeconds(1));
        // Shouldn't have any stats, as no aggregation
        var metrics = collector.GetMetrics();
        metrics.Metrics.Should().BeNull();
        metrics.Distributions.Should().BeNull();
    }

    [Fact]
    public async Task AggregatesOnShutdown()
    {
        var collector = new MetricsTelemetryCollector(Timeout.InfiniteTimeSpan);
        collector.Record(PublicApiUsage.Tracer_Configure);
        collector.RecordDistributionInitTime(MetricTags.InitializationComponent.Managed, 22);

        await collector.DisposeAsync();
        var metrics = collector.GetMetrics();

        metrics.Metrics.Should().BeEquivalentTo(new[]
        {
            new
            {
                Metric = "public_api",
                Points = new[] { new { Value = 1 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { PublicApiUsage.Tracer_Configure.ToStringFast() },
                Common = false,
                Namespace = (string)null,
            },
        });

        metrics.Distributions.Should().BeEquivalentTo(new[]
        {
            new
            {
                Metric = Distribution.InitTime.GetName(),
                Tags = new[] { "component:managed" },
                Points = new[] {  22 },
                Common = true,
                Namespace = NS.General,
            },
        });
    }

    [Theory]
    [InlineData(null)]
    [InlineData("1.2.3")]
    public void AllMetricsAreReturned(string wafVersion)
    {
        var collector = new MetricsTelemetryCollector(Timeout.InfiniteTimeSpan);
        collector.Record(PublicApiUsage.Tracer_Configure);
        collector.Record(PublicApiUsage.Tracer_Configure);
        collector.Record(PublicApiUsage.Tracer_Ctor);
        collector.RecordCountSpanFinished(15);
        collector.RecordCountIntegrationsError(MetricTags.IntegrationName.Aerospike, MetricTags.InstrumentationError.Invoker);
        collector.RecordCountSpanCreated(MetricTags.IntegrationName.Aerospike);
        collector.RecordCountSpanDropped(MetricTags.DropReason.P0Drop, 23);
        collector.RecordCountLogCreated(MetricTags.LogLevel.Debug, 3);
        collector.RecordCountWafInit(4);
        collector.RecordCountWafRequests(MetricTags.WafAnalysis.Normal, 5);
        collector.RecordGaugeStatsBuckets(234);
        collector.RecordDistributionInitTime(MetricTags.InitializationComponent.Total, 23);
        collector.RecordDistributionInitTime(MetricTags.InitializationComponent.Total, 46);
        collector.RecordDistributionInitTime(MetricTags.InitializationComponent.Managed, 52);

        collector.AggregateMetrics();

        collector.Record(PublicApiUsage.Tracer_Ctor);
        collector.Record(PublicApiUsage.Tracer_Ctor);
        collector.Record(PublicApiUsage.TracerSettings_Build);
        collector.RecordCountSpanFinished(3);
        collector.RecordCountTraceSegmentCreated(MetricTags.TraceContinuation.New, 2);
        collector.RecordGaugeStatsBuckets(15);
        collector.RecordGaugeDirectLogQueue(7);
        collector.RecordDistributionInitTime(MetricTags.InitializationComponent.Managed, 22);
        collector.RecordDistributionInitTime(MetricTags.InitializationComponent.Rcm, 15);

        collector.AggregateMetrics();

        var expectedWafTag = "waf_version:unknown";

        if (wafVersion is not null)
        {
            collector.SetWafVersion(wafVersion);
            expectedWafTag = $"waf_version:{wafVersion}";
        }

        using var scope = new AssertionScope();
        scope.FormattingOptions.MaxLines = 1000;

        var metrics = collector.GetMetrics();

        var metrics2 = collector.GetMetrics();
        metrics2.Metrics.Should().BeNull();
        metrics2.Distributions.Should().BeNull();

        metrics.Metrics.Should().BeEquivalentTo(new[]
        {
            new
            {
                Metric = "public_api",
                Points = new[] { new { Value = 2 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { PublicApiUsage.Tracer_Configure.ToStringFast() },
                Common = false,
                Namespace = (string)null,
            },
            new
            {
                Metric = "public_api",
                Points = new[] { new { Value = 1 }, new { Value = 2 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { PublicApiUsage.Tracer_Ctor.ToStringFast() },
                Common = false,
                Namespace = (string)null,
            },
            new
            {
                Metric = "public_api",
                Points = new[] { new { Value = 1 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { PublicApiUsage.TracerSettings_Build.ToStringFast() },
                Common = false,
                Namespace = (string)null,
            },
            new
            {
                Metric = Count.IntegrationsError.GetName(),
                Points = new[] { new { Value = 1 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { "integration_name:aerospike", "error_type:invoker" },
                Common = true,
                Namespace = (string)null,
            },
            new
            {
                Metric = Count.SpanCreated.GetName(),
                Points = new[] { new { Value = 1 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { "integration_name:aerospike" },
                Common = true,
                Namespace = (string)null,
            },
            new
            {
                Metric = Count.SpanFinished.GetName(),
                Points = new[] { new { Value = 15 }, new { Value = 3 } },
                Type = TelemetryMetricType.Count,
                Tags = (string[])null,
                Common = true,
                Namespace = (string)null,
            },
            new
            {
                Metric = Count.SpanDropped.GetName(),
                Points = new[] { new { Value = 23 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { "reason:p0_drop" },
                Common = true,
                Namespace = (string)null,
            },
            new
            {
                Metric = Count.LogCreated.GetName(),
                Points = new[] { new { Value = 3 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { "level:debug" },
                Common = true,
                Namespace = NS.General,
            },
            new
            {
                Metric = Count.WafInit.GetName(),
                Points = new[] { new { Value = 4 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { expectedWafTag },
                Common = true,
                Namespace = NS.ASM,
            },
            new
            {
                Metric = Count.WafRequests.GetName(),
                Points = new[] { new { Value = 5 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { expectedWafTag, "rule_triggered:false", "request_blocked:false", "waf_timeout:false", "request_excluded:false" },
                Common = true,
                Namespace = NS.ASM,
            },
            new
            {
                Metric = Count.TraceSegmentCreated.GetName(),
                Points = new[] { new { Value = 2 } },
                Type = TelemetryMetricType.Count,
                Tags = new[] { "new_continued:new" },
                Common = true,
                Namespace = (string)null,
            },
            new
            {
                Metric = Gauge.StatsBuckets.GetName(),
                Points = new[] { new { Value = 234 }, new { Value = 15 } },
                Type = TelemetryMetricType.Gauge,
                Tags = (string[])null,
                Common = true,
                Namespace = (string)null,
            },
            new
            {
                Metric = Gauge.DirectLogQueue.GetName(),
                Points = new[] { new { Value = 7 } },
                Type = TelemetryMetricType.Gauge,
                Tags = (string[])null,
                Common = false,
                Namespace = (string)null,
            },
        });

        metrics.Distributions.Should().BeEquivalentTo(new[]
        {
            new
            {
                Metric = Distribution.InitTime.GetName(),
                Tags = new[] { "component:total" },
                Points = new[] { 23, 46 },
                Common = true,
                Namespace = NS.General,
            },
            new
            {
                Metric = Distribution.InitTime.GetName(),
                Tags = new[] { "component:managed" },
                Points = new[] {  52, 22 },
                Common = true,
                Namespace = NS.General,
            },
            new
            {
                Metric = Distribution.InitTime.GetName(),
                Tags = new[] { "component:rcm" },
                Points = new[] {  15 },
                Common = true,
                Namespace = NS.General,
            },
        });
    }

    [Fact]
    public void ShouldAggregateMetricsAutomatically()
    {
        var aggregationPeriod = TimeSpan.FromMilliseconds(500);

        var collector = new MetricsTelemetryCollector(aggregationPeriod);
        // theoretically ~10 aggregations in this time period
        var count = 0;
        while (count < 50)
        {
            collector.RecordCountSpanFinished(1);
            Thread.Sleep(100);
            count++;
        }

        var metrics = collector.GetMetrics();
        metrics.Metrics.Should()
               .ContainSingle(x => x.Metric == Count.SpanFinished.GetName())
               .Which.Points.Should()
               .NotBeEmpty(); // we expect ~10 points, but don't assert that number to avoid flakiness
    }
}
