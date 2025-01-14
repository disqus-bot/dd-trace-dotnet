﻿// <copyright file="ProductsTelemetryCollectorTests.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System.Linq;
using Datadog.Trace.Telemetry;
using FluentAssertions;
using Xunit;

namespace Datadog.Trace.Tests.Telemetry;

public class ProductsTelemetryCollectorTests
{
    [Fact]
    public void DoesNotHaveChangesWhenNoCalls()
    {
        var collector = new ProductsTelemetryCollector();

        collector.HasChanges().Should().BeFalse();
        collector.GetData().Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Data.AllEnabledPermutations), MemberType = typeof(Data))]
    public void HasChangesWhenSingleProductChanged(bool? appsecEnabled, bool? profilerEnabled, bool? debuggerEnabled)
    {
        var collector = new ProductsTelemetryCollector();
        if (appsecEnabled is not null)
        {
            collector.ProductChanged(TelemetryProductType.AppSec, enabled: appsecEnabled.Value, error: null);
        }

        if (profilerEnabled is not null)
        {
            collector.ProductChanged(TelemetryProductType.Profiler, enabled: profilerEnabled.Value, error: null);
        }

        if (debuggerEnabled is not null)
        {
            collector.ProductChanged(TelemetryProductType.DynamicInstrumentation, enabled: debuggerEnabled.Value, error: null);
        }

        var data = collector.GetData();
        (data?.Appsec?.Enabled).Should().Be(appsecEnabled);
        (data?.Profiler?.Enabled).Should().Be(profilerEnabled);
        (data?.DynamicInstrumentation?.Enabled).Should().Be(debuggerEnabled);
    }

    [Fact]
    public void DoesNotHaveChangesIfNoChanges()
    {
        // This behaviour isn't _necessary_ but it documents the current existing behaviour
        var collector = new ProductsTelemetryCollector();

        collector.ProductChanged(TelemetryProductType.AppSec, enabled: true, error: null);
        collector.HasChanges().Should().BeTrue();
        collector.GetData().Should().NotBeNull();

        collector.HasChanges().Should().BeFalse();
        collector.GetData().Should().BeNull();
    }

    [Fact]
    public void HasChangesWhenSettingTheSameValue()
    {
        // This behaviour isn't _necessary_ but it documents the current existing behaviour
        var collector = new ProductsTelemetryCollector();

        collector.ProductChanged(TelemetryProductType.AppSec, enabled: true, error: null);
        collector.HasChanges().Should().BeTrue();
        collector.GetData().Should().NotBeNull();

        collector.ProductChanged(TelemetryProductType.AppSec, enabled: true, error: null);
        collector.HasChanges().Should().BeTrue();
        collector.GetData().Should().NotBeNull();
    }

    [Fact]
    public void IncludesErrorInData()
    {
        var collector = new ProductsTelemetryCollector();

        var errorCode = TelemetryErrorCode.AppsecConfigurationError;
        var errorMessage = "some error";

        collector.ProductChanged(TelemetryProductType.AppSec, enabled: false, error: new ErrorData(errorCode, errorMessage));

        collector.HasChanges().Should().BeTrue();
        var data = collector.GetData();
        (data?.Appsec?.Enabled).Should().BeFalse();
        data.Appsec.Error.Should().NotBeNull();
        data.Appsec.Error.Value.Code.Should().Be((int)errorCode);
        data.Appsec.Error.Value.Message.Should().Be(errorMessage);
    }

    public class Data
    {
        public static TheoryData<bool?, bool?, bool?> AllEnabledPermutations()
        {
            var values = new bool?[] { true, false, null };
            var data = new TheoryData<bool?, bool?, bool?>();
            var allValues = from appsec in values
                            from profiler in values
                            from debugger in values
                            select (appsec, profiler, debugger);

            foreach (var (appsec, profiler, debugger) in allValues)
            {
                data.Add(appsec, profiler, debugger);
            }

            return data;
        }
    }
}
