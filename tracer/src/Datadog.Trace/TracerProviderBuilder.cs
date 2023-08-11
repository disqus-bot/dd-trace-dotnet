// <copyright file="TracerProviderBuilder.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

#nullable enable

using System;
using System.Collections.Generic;
using Datadog.Trace.Configuration;
using Datadog.Trace.Configuration.Telemetry;

namespace Datadog.Trace;

#pragma warning disable SA1600 // Elements should be documented
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public class TracerProviderBuilder
{
    private Dictionary<string, string?> _settings = new();

    internal TracerProviderBuilder()
    {
    }

    public static TracerProviderBuilder Create() => new();

    public TracerProviderBuilder AddSetting(string key, string? value)
    {
        _settings.Add(key, value);
        return this;
    }

    public TracerProvider Build()
    {
        if (_settings.Count > 0)
        {
            ConfigureFromManual(_settings);
        }

        return new();
    }

    // Important: This method will be modified by automatic instrumentation.
    // Instead of calling this assembly's Tracer.ConfigureFromManual(settings),
    // it will call the other Tracer type
    internal static void ConfigureFromManual(object settings)
    {
#pragma warning disable DD0002 // Incorrect usage of public API
        Tracer.ConfigureFromManual(settings);
#pragma warning restore DD0002 // Incorrect usage of public API
    }
}
