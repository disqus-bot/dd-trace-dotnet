﻿// <auto-generated/>
#nullable enable

namespace Datadog.Trace.Configuration;
partial record ImmutableTracerSettings
{

        /// <summary>
        /// Gets the default environment name applied to all spans.
        /// </summary>
        /// <seealso cref="ConfigurationKeys.Environment"/>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public string? Environment
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)144);
            return EnvironmentInternal;
        }
    }

        /// <summary>
        /// Gets the service name applied to top-level spans and used to build derived service names.
        /// </summary>
        /// <seealso cref="ConfigurationKeys.ServiceName"/>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public string? ServiceName
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)154);
            return ServiceNameInternal;
        }
    }

        /// <summary>
        /// Gets the version tag applied to all spans.
        /// </summary>
        /// <seealso cref="ConfigurationKeys.ServiceVersion"/>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public string? ServiceVersion
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)155);
            return ServiceVersionInternal;
        }
    }

        /// <summary>
        /// Gets a value indicating whether tracing is enabled.
        /// Default is <c>true</c>.
        /// </summary>
        /// <seealso cref="ConfigurationKeys.TraceEnabled"/>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public bool TraceEnabled
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)158);
            return TraceEnabledInternal;
        }
    }

        /// <summary>
        /// Gets the exporter settings that dictate how the tracer exports data.
        /// </summary>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public Datadog.Trace.Configuration.ImmutableExporterSettings Exporter
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)145);
            return ExporterInternal;
        }
    }

#pragma warning disable CS1574 // AnalyticsEnabled is obsolete
        /// <summary>
        /// Gets a value indicating whether default Analytics are enabled.
        /// Settings this value is a shortcut for setting
        /// <see cref="Configuration.IntegrationSettings.AnalyticsEnabled"/> on some predetermined integrations.
        /// See the documentation for more details.
        /// </summary>
        /// <seealso cref="ConfigurationKeys.GlobalAnalyticsEnabled"/>
#pragma warning restore CS1574
    [System.Obsolete("App Analytics has been replaced by Tracing without Limits. For more information see https://docs.datadoghq.com/tracing/legacy_app_analytics/")]
    [Datadog.Trace.SourceGenerators.PublicApi]
    public bool AnalyticsEnabled
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)142);
            return AnalyticsEnabledInternal;
        }
    }

        /// <summary>
        /// Gets a value indicating whether correlation identifiers are
        /// automatically injected into the logging context.
        /// Default is <c>false</c>.
        /// </summary>
        /// <seealso cref="ConfigurationKeys.LogsInjectionEnabled"/>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public bool LogsInjectionEnabled
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)152);
            return LogsInjectionEnabledInternal;
        }
    }

        /// <summary>
        /// Gets a value indicating the maximum number of traces set to AutoKeep (p1) per second.
        /// Default is <c>100</c>.
        /// </summary>
        /// <seealso cref="ConfigurationKeys.TraceRateLimit"/>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public int MaxTracesSubmittedPerSecond
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)153);
            return MaxTracesSubmittedPerSecondInternal;
        }
    }

        /// <summary>
        /// Gets a value indicating custom sampling rules.
        /// </summary>
        /// <seealso cref="ConfigurationKeys.CustomSamplingRules"/>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public string? CustomSamplingRules
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)143);
            return CustomSamplingRulesInternal;
        }
    }

        /// <summary>
        /// Gets a value indicating a global rate for sampling.
        /// </summary>
        /// <seealso cref="ConfigurationKeys.GlobalSamplingRate"/>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public double? GlobalSamplingRate
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)146);
            return GlobalSamplingRateInternal;
        }
    }

        /// <summary>
        /// Gets a collection of <see cref="IntegrationsInternal"/> keyed by integration name.
        /// </summary>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public Datadog.Trace.Configuration.ImmutableIntegrationSettingsCollection Integrations
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)150);
            return IntegrationsInternal;
        }
    }

        /// <summary>
        /// Gets the global tags, which are applied to all <see cref="Span"/>s.
        /// </summary>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public System.Collections.Generic.IReadOnlyDictionary<string, string> GlobalTags
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)147);
            return GlobalTagsInternal;
        }
    }

        /// <summary>
        /// Gets the map of header keys to tag names, which are applied to the root <see cref="Span"/>
        /// of incoming and outgoing requests.
        /// </summary>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public System.Collections.Generic.IReadOnlyDictionary<string, string> HeaderTags
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)149);
            return HeaderTagsInternal;
        }
    }

        /// <summary>
        /// Gets the map of metadata keys to tag names, which are applied to the root <see cref="Span"/>
        /// of incoming and outgoing GRPC requests.
        /// </summary>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public System.Collections.Generic.IReadOnlyDictionary<string, string> GrpcTags
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)148);
            return GrpcTagsInternal;
        }
    }

        /// <summary>
        /// Gets a value indicating whether internal metrics
        /// are enabled and sent to DogStatsd.
        /// </summary>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public bool TracerMetricsEnabled
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)159);
            return TracerMetricsEnabledInternal;
        }
    }

        /// <summary>
        /// Gets a value indicating whether stats are computed on the tracer side
        /// </summary>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public bool StatsComputationEnabled
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)157);
            return StatsComputationEnabledInternal;
        }
    }

        /// <summary>
        /// Gets a value indicating whether a span context should be created on exiting a successful Kafka
        /// Consumer.Consume() call, and closed on entering Consumer.Consume().
        /// </summary>
        /// <seealso cref="ConfigurationKeys.KafkaCreateConsumerScopeEnabled"/>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public bool KafkaCreateConsumerScopeEnabled
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)151);
            return KafkaCreateConsumerScopeEnabledInternal;
        }
    }

        /// <summary>
        /// Gets a value indicating whether the diagnostic log at startup is enabled
        /// </summary>
    [Datadog.Trace.SourceGenerators.PublicApi]
    public bool StartupDiagnosticLogEnabled
    {
        get
        {
            Datadog.Trace.Telemetry.TelemetryFactory.Metrics.Record(
                (Datadog.Trace.Telemetry.Metrics.PublicApiUsage)156);
            return StartupDiagnosticLogEnabledInternal;
        }
    }
}