// <copyright file="SpanContextPropagatorTests.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Linq;
using System.Net;
using Datadog.Trace.ExtensionMethods;
using Datadog.Trace.Headers;
using Datadog.Trace.TestHelpers;
using Moq;
using Xunit;

namespace Datadog.Trace.Tests
{
    public class SpanContextPropagatorTests
    {
        private static readonly string TestPrefix = "test.prefix";

        public static IEnumerable<object[]> GetHeaderCollectionImplementations()
        {
            return GetHeaderCollectionFactories().Select(factory => new object[] { factory() });
        }

        public static IEnumerable<object[]> GetHeaderCollectionImplementationsAndOptionsToNormalizePeriods()
        {
            return from headersFactory in GetHeaderCollectionFactories()
                   from normalizePeriods in new object[] { true, false }
                   select new[] { headersFactory(), normalizePeriods };
        }

        public static IEnumerable<object[]> GetHeadersInvalidIdsCartesianProduct()
        {
            return from headersFactory in GetHeaderCollectionFactories()
                   from invalidId in HeadersCollectionTestHelpers.GetInvalidIds().SelectMany(i => i)
                   select new[] { headersFactory(), invalidId };
        }

        public static IEnumerable<object[]> GetHeadersInvalidIntegerSamplingPrioritiesCartesianProduct()
        {
            return from headersFactory in GetHeaderCollectionFactories()
                   from invalidSamplingPriority in HeadersCollectionTestHelpers.GetInvalidIntegerSamplingPriorities().SelectMany(i => i)
                   select new[] { headersFactory(), invalidSamplingPriority };
        }

        public static IEnumerable<object[]> GetHeadersInvalidNonIntegerSamplingPrioritiesCartesianProduct()
        {
            return from headersFactory in GetHeaderCollectionFactories()
                   from invalidSamplingPriority in HeadersCollectionTestHelpers.GetInvalidNonIntegerSamplingPriorities().SelectMany(i => i)
                   select new[] { headersFactory(), invalidSamplingPriority };
        }

        internal static IEnumerable<Func<IHeadersCollection>> GetHeaderCollectionFactories()
        {
            yield return () => WebRequest.CreateHttp("http://localhost").Headers.Wrap();
            yield return () => new NameValueCollection().Wrap();
        }

        [Theory]
        [MemberData(nameof(GetHeaderCollectionImplementations))]
        internal void ExtractHeaderTags_MatchesCaseInsensitiveHeaders(IHeadersCollection headers)
        {
            // Initialize constants
            const string customHeader1Name = "dd-custom-header1";
            const string customHeader1Value = "match1";
            const string customHeader1TagName = "custom-header1-tag";

            const string customHeader2Name = "DD-CUSTOM-HEADER-MISMATCHING-CASE";
            const string customHeader2Value = "match2";
            const string customHeader2TagName = "custom-header2-tag";
            var customHeader2LowercaseHeaderName = customHeader2Name.ToLowerInvariant();

            // Initialize SpanContextPropagator and HeaderNormalizer mock
            var spanContextPropagator = CreateSpanContextPropagatorWithStrictMock();

            // Add headers
            headers.Add(customHeader1Name, customHeader1Value);
            headers.Add(customHeader2Name, customHeader2Value);

            // Initialize header-tag arguments and expectations
            var headerTags = new Dictionary<string, string>();
            headerTags.Add(customHeader1Name, customHeader1TagName);
            headerTags.Add(customHeader2LowercaseHeaderName, customHeader2TagName);

            var expectedResults = new Dictionary<string, string>();
            expectedResults.Add(customHeader1TagName, customHeader1Value);
            expectedResults.Add(customHeader2TagName, customHeader2Value);

            // Test
            var tagsFromHeader = spanContextPropagator.ExtractHeaderTags(headers, headerTags, TestPrefix);

            // Assert
            Assert.NotNull(tagsFromHeader);
            Assert.Equal(expectedResults, tagsFromHeader);
        }

        [Theory]
        [MemberData(nameof(GetHeaderCollectionImplementations))]
        internal void ExtractHeaderTags_EmptyHeaders_AddsNoTags(IHeadersCollection headers)
        {
            // Initialize SpanContextPropagator and HeaderNormalizer mock
            var spanContextPropagator = CreateSpanContextPropagatorWithStrictMock();

            // Do not add headers

            // Initialize header-tag arguments and expectations
            var headerTags = new Dictionary<string, string>();
            headerTags.Add("x-header-test-runner", "test-runner");

            var expectedResults = new Dictionary<string, string>();

            // Test
            var tagsFromHeader = spanContextPropagator.ExtractHeaderTags(headers, headerTags, TestPrefix);

            // Assert
            Assert.NotNull(tagsFromHeader);
            Assert.Equal(expectedResults, tagsFromHeader);
        }

        [Theory]
        [MemberData(nameof(GetHeaderCollectionImplementations))]
        internal void ExtractHeaderTags_EmptyHeaderTags_AddsNoTags(IHeadersCollection headers)
        {
            // Initialize SpanContextPropagator and HeaderNormalizer mock
            var spanContextPropagator = CreateSpanContextPropagatorWithStrictMock();

            // Add headers
            headers.Add("x-header-test-runner", "xunit");

            // Initialize header-tag arguments and expectations
            var headerToTagMap = new Dictionary<string, string>();
            var expectedResults = new Dictionary<string, string>();

            // Test
            var tagsFromHeader = spanContextPropagator.ExtractHeaderTags(headers, headerToTagMap, TestPrefix);

            // Assert
            Assert.NotNull(tagsFromHeader);
            Assert.Equal(expectedResults, tagsFromHeader);
        }

        [Theory]
        [MemberData(nameof(GetHeaderCollectionImplementationsAndOptionsToNormalizePeriods))]
        internal void ExtractHeaderTags_ForEmptyStringMappings_CreatesNormalizedTagWithPrefix(IHeadersCollection headers, bool normalizePeriods)
        {
            const string header1 = "x-header-test-runner";
            const string header2 = "x-header-1datadog-any";
            // Used to avoid verifying methods with out params
            const string normalizerPrefix = "normalized.";

            // Initialize SpanContextPropagator and HeaderNormalizer mock
            var spanContextPropagator = CreateSpanContextPropagatorWithSetupMock(normalizerPrefix, normalizePeriods, header1, header2);

            // Add headers
            headers.Add(header1, "xunit");
            headers.Add(header2, "true");

            // Initialize header-tag arguments and expectations
            var headerToTagMap = new Dictionary<string, string>
            {
                { header1, string.Empty },
                { header2, string.Empty },
            };

            var expectedResults = new Dictionary<string, string>
            {
                { TestPrefix + "." + normalizerPrefix + header1, "xunit" },
                { TestPrefix + "." + normalizerPrefix + header2, "true" }
            };

            // Test
            var tagsFromHeader = spanContextPropagator.ExtractHeaderTags(headers, headerToTagMap, TestPrefix);

            // Assert
            Assert.NotNull(tagsFromHeader);
            Assert.Equal(expectedResults, tagsFromHeader);
        }

        [Theory]
        [MemberData(nameof(GetHeaderCollectionImplementations))]
        internal void Extract_EmptyHeadersReturnsNull(IHeadersCollection headers)
        {
            // Initialize SpanContextPropagator and HeaderNormalizer mock
            var spanContextPropagator = CreateSpanContextPropagatorWithStrictMock();

            var resultContext = spanContextPropagator.Extract(headers);
            Assert.Null(resultContext);
        }

        [Theory]
        [MemberData(nameof(GetHeaderCollectionImplementations))]
        internal void InjectExtract_Identity(IHeadersCollection headers)
        {
            const int traceId = 9;
            const int spanId = 7;
            const SamplingPriority samplingPriority = SamplingPriority.UserKeep;
            const string origin = "synthetics";

            // Initialize SpanContextPropagator and HeaderNormalizer mock
            var spanContextPropagator = CreateSpanContextPropagatorWithStrictMock();

            var context = new SpanContext(traceId, spanId, samplingPriority, null, origin);
            spanContextPropagator.Inject(context, headers);
            var resultContext = spanContextPropagator.Extract(headers);

            Assert.NotNull(resultContext);
            Assert.Equal(context.SpanId, resultContext.SpanId);
            Assert.Equal(context.TraceId, resultContext.TraceId);
            Assert.Equal(context.SamplingPriority, resultContext.SamplingPriority);
            Assert.Equal(context.Origin, resultContext.Origin);
        }

        [Theory]
        [MemberData(nameof(GetHeadersInvalidIdsCartesianProduct))]
        internal void Extract_InvalidTraceId(IHeadersCollection headers, string traceId)
        {
            const string spanId = "7";
            const string samplingPriority = "2";
            const string origin = "synthetics";

            // Initialize SpanContextPropagator and HeaderNormalizer mock
            var spanContextPropagator = CreateSpanContextPropagatorWithStrictMock();

            InjectContext(headers, traceId, spanId, samplingPriority, origin);
            var resultContext = spanContextPropagator.Extract(headers);

            // invalid traceId should return a null context even if other values are set
            Assert.Null(resultContext);
        }

        [Theory]
        [MemberData(nameof(GetHeadersInvalidIdsCartesianProduct))]
        internal void Extract_InvalidSpanId(IHeadersCollection headers, string spanId)
        {
            const ulong traceId = 9;
            const SamplingPriority samplingPriority = SamplingPriority.UserKeep;
            const string origin = "synthetics";

            InjectContext(
                headers,
                traceId.ToString(CultureInfo.InvariantCulture),
                spanId,
                ((int)samplingPriority).ToString(CultureInfo.InvariantCulture),
                origin);

            // Initialize SpanContextPropagator and HeaderNormalizer mock
            var spanContextPropagator = CreateSpanContextPropagatorWithStrictMock();

            var resultContext = spanContextPropagator.Extract(headers);

            Assert.NotNull(resultContext);
            Assert.Equal(traceId, resultContext.TraceId);
            Assert.Equal(default, resultContext.SpanId);
            Assert.Equal(samplingPriority, resultContext.SamplingPriority);
            Assert.Equal(origin, resultContext.Origin);
        }

        [Theory]
        [MemberData(nameof(GetHeadersInvalidIntegerSamplingPrioritiesCartesianProduct))]
        internal void Extract_InvalidIntegerSamplingPriority(IHeadersCollection headers, string samplingPriority)
        {
            // if the extracted sampling priority is a valid integer, pass it along as is,
            // even if we don't recognize its value to allow forward compatibility with newly added values.
            const ulong traceId = 9;
            const ulong spanId = 7;
            const string origin = "synthetics";

            InjectContext(
                headers,
                traceId.ToString(CultureInfo.InvariantCulture),
                spanId.ToString(CultureInfo.InvariantCulture),
                samplingPriority,
                origin);

            // Initialize SpanContextPropagator and HeaderNormalizer mock
            var spanContextPropagator = CreateSpanContextPropagatorWithStrictMock();

            var resultContext = spanContextPropagator.Extract(headers);

            Assert.NotNull(resultContext);
            Assert.Equal(traceId, resultContext.TraceId);
            Assert.Equal(spanId, resultContext.SpanId);
            Assert.NotNull(resultContext.SamplingPriority);
            Assert.Equal(samplingPriority, ((int)resultContext.SamplingPriority).ToString());
            Assert.Equal(origin, resultContext.Origin);
        }

        [Theory]
        [MemberData(nameof(GetHeadersInvalidNonIntegerSamplingPrioritiesCartesianProduct))]
        internal void Extract_InvalidNonIntegerSamplingPriority(IHeadersCollection headers, string samplingPriority)
        {
            // ignore the extracted sampling priority if it is not a valid integer
            const ulong traceId = 9;
            const ulong spanId = 7;
            const string origin = "synthetics";

            InjectContext(
                headers,
                traceId.ToString(CultureInfo.InvariantCulture),
                spanId.ToString(CultureInfo.InvariantCulture),
                samplingPriority,
                origin);

            // Initialize SpanContextPropagator and HeaderNormalizer mock
            var spanContextPropagator = CreateSpanContextPropagatorWithStrictMock();

            var resultContext = spanContextPropagator.Extract(headers);

            Assert.NotNull(resultContext);
            Assert.Equal(traceId, resultContext.TraceId);
            Assert.Equal(spanId, resultContext.SpanId);
            Assert.Null(resultContext.SamplingPriority);
            Assert.Equal(origin, resultContext.Origin);
        }

        private static void InjectContext(IHeadersCollection headers, string traceId, string spanId, string samplingPriority, string origin)
        {
            headers.Add(HttpHeaderNames.TraceId, traceId);
            headers.Add(HttpHeaderNames.ParentId, spanId);
            headers.Add(HttpHeaderNames.SamplingPriority, samplingPriority);
            headers.Add(HttpHeaderNames.Origin, origin);
        }

        private static SpanContextPropagator CreateSpanContextPropagatorWithStrictMock()
        {
            var mock = new Mock<IHeaderNormalizer>(MockBehavior.Strict);
            return new SpanContextPropagator(mock.Object);
        }

        private static SpanContextPropagator CreateSpanContextPropagatorWithSetupMock(string normalizerPrefix, bool normalizePeriods, params string[] normalizedStringToReturn)
        {
            var headerNormalizerMock = new Mock<IHeaderNormalizer>();
            foreach (var stringToNormalize in normalizedStringToReturn)
            {
                var outValue = normalizerPrefix + stringToNormalize;

                if (normalizePeriods)
                {
                    headerNormalizerMock
                       .Setup(normalizer => normalizer.TryConvertToNormalizedTagNameIncludingPeriods(stringToNormalize, out outValue))
                       .Returns(true);
                }
                else
                {
                    headerNormalizerMock
                       .Setup(normalizer => normalizer.TryConvertToNormalizedTagName(stringToNormalize, out outValue))
                       .Returns(true);
                }
            }

            return new SpanContextPropagator(headerNormalizerMock.Object);
        }
    }
}
