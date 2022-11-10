// <copyright file="ITaintedObject.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
#nullable enable

namespace Datadog.Trace.Iast;

internal interface ITaintedObject
{
    public object? Value { get; }

    bool IsAlive { get; }

    public ITaintedObject? Next { get; set; }

    public int PositiveHashCode { get; }

    public WeakReference Weak { get; }
}
