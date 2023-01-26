// <copyright file="NetActivitySdkTests.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Datadog.Trace.Configuration;
using Datadog.Trace.TestHelpers;
using FluentAssertions;
using FluentAssertions.Execution;
using VerifyXunit;
using Xunit;
using Xunit.Abstractions;

namespace Datadog.Trace.ClrProfiler.IntegrationTests
{
    [UsesVerify]
    public class NetActivitySdkTests : TracingIntegrationTest
    {
        public NetActivitySdkTests(ITestOutputHelper output)
            : base("NetActivitySdk", output)
        {
            // Intentionally unset service name and version, which may be derived from OTEL SDK
            SetServiceName(string.Empty);
            SetServiceVersion(string.Empty);
        }

        public override Result ValidateIntegrationSpan(MockSpan span) =>
            span.IsOpenTelemetry(
                resources: new HashSet<string>
                {
                    "service.instance.id",
                    "service.name",
                    "service.version"
                },
                excludeTags: new HashSet<string>
                {
                    "attribute-string",
                    "attribute-int",
                    "attribute-bool",
                    "attribute-double",
                    "attribute-stringArray",
                    "attribute-stringArrayEmpty",
                    "attribute-intArray",
                    "attribute-intArrayEmpty",
                    "attribute-boolArray",
                    "attribute-boolArrayEmpty",
                    "attribute-doubleArray",
                    "attribute-doubleArrayEmpty",
                    "set-string"
                });

        [SkippableFact]
        [Trait("Category", "EndToEnd")]
        [Trait("RunOnWindows", "True")]
        public async Task SubmitsTraces()
        {
            SetEnvironmentVariable("DD_TRACE_OTEL_ENABLED", "true");

            using (var telemetry = this.ConfigureTelemetry())
            using (var agent = EnvironmentHelper.GetMockAgent())
            using (RunSampleAndWaitForExit(agent))
            {
                const int expectedSpanCount = 23;
                var spans = agent.WaitForSpans(expectedSpanCount);

                using var s = new AssertionScope();
                spans.Count.Should().Be(expectedSpanCount);

                var myServiceNameSpans = spans.Where(s => s.Service == "MyServiceName");

                ValidateIntegrationSpans(myServiceNameSpans, expectedServiceName: "MyServiceName");

                var settings = VerifyHelper.GetSpanVerifierSettings();
                await VerifyHelper.VerifySpans(spans, settings)
                                  .UseFileName(nameof(NetActivitySdkTests));

                telemetry.AssertIntegrationEnabled(IntegrationId.OpenTelemetry);
            }
        }
    }
}
