// <copyright file="ApiSecurity.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using Datadog.Trace.AppSec.Waf;
using Datadog.Trace.Sampling;
using Datadog.Trace.Vendors.Newtonsoft.Json;
using Datadog.Trace.Vendors.Serilog;

namespace Datadog.Trace.AppSec;

internal class ApiSecurity
{
    private readonly OverheadController _overheadController;

    public ApiSecurity(SecuritySettings securitySettings)
    {
        _overheadController = new(1, securitySettings.ApiSecuritySampling);
        // todo: later, will be enabled by default, depending on if Security is enabled
        Enabled = securitySettings.ApiSecurityEnabled;
    }

    public bool Enabled { get; }

    public void TryTellWafToAnalyzeSchema(IDictionary<string, object> args)
    {
        if (Enabled && _overheadController.AcquireRequest())
        {
            args.Add(AddressesConstants.WafContextSettings, new Dictionary<string, string> { { "extract-schema", "true" } });
        }
    }

    public void ReleaseRequest() => _overheadController.ReleaseRequest();
}
