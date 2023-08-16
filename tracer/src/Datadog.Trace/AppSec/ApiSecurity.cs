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

    internal void ReportSchema(IResult? result, Span localRootSpan)
    {
        var resultDerivatives = result?.Derivatives;
        if (resultDerivatives is null or { Count: 0 })
        {
            return;
        }

        const string prefix = "_dd.appsec.s.";
        var dic = new Dictionary<string, string>
        {
            { AddressesConstants.RequestBody + ".schema", prefix + "req.body" },
            { AddressesConstants.RequestHeaderNoCookies + ".schema", prefix + "req.headers" },
            { AddressesConstants.RequestQuery + ".schema", prefix + "req.query" },
            { AddressesConstants.RequestPathParams + ".schema", prefix + "req.params" },
            { AddressesConstants.ResponseBody + ".schema", prefix + "res.body" },
            { AddressesConstants.ResponseHeaderNoCookies + ".schema", prefix + "res.headers" }
        };
        foreach (var derivative in resultDerivatives)
        {
            var exists = dic.TryGetValue(derivative.Key, out var key);
            if (exists)
            {
                var serializeObject = JsonConvert.SerializeObject(derivative.Value);
                var bytes = Encoding.UTF8.GetBytes(serializeObject);
                using var memoryStream = new MemoryStream();
                using var gZipStream = new GZipStream(memoryStream, CompressionMode.Compress);
                gZipStream.Write(bytes, 0, bytes.Length);
                var gzipBase64 = Convert.ToBase64String(bytes);
                localRootSpan.SetTag(key, gzipBase64);
            }
            else
            {
                Log.Warning("Derivative key unknown {Key}", derivative.Key);
            }
        }
    }

    public void ReleaseRequest() => _overheadController.ReleaseRequest();
}
