// <copyright file="HardcodedSecretsAnalyzer.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace.AppSec;
using Datadog.Trace.AppSec.Waf;
using Datadog.Trace.ClrProfiler;
using Datadog.Trace.Configuration;
using Datadog.Trace.Debugger.PInvoke;
using Datadog.Trace.Logging;
using Datadog.Trace.Vendors.dnlib.DotNet.Resources;

namespace Datadog.Trace.Iast.Analyzers;

internal class HardcodedSecretsAnalyzer
{
    private static readonly IDatadogLogger Log = DatadogLogging.GetLoggerFor<HardcodedSecretsAnalyzer>();
    private static HardcodedSecretsAnalyzer? _instance = null;

    private static string[] _excludedAssemblies = new[]
    {
        "System*",
        "Datadog.*",
        "Kudu*",
        "Microsoft*",
        "MSBuild",
        "dotnet",
        "netstandard",
        "AspNet.*",
        "msvcm90*",
        "Mono.*",
        "NuGet.*",
        "PCRE.*",
        "Antlr*",
        "Azure.Messaging.ServiceBus*",
        "PostSharp",
        "SMDiagnostics",
        "testhost",
        "WebGrease",
        "YamlDotNet",
        "EnvSettings*",
        "EntityFramework*",
        "linq2db*",
        "Newtonsoft.Json*",
        "log4net*",
        "Autofac*",
        "StackExchange*",
        "BundleTransformer*",
        "LibSassHost*",
        "ClearScript*",
        "NewRelic*",
        "AppDynamics*",
        "NProfiler*",
        "KTJdotnetTls*",
        "KTJUniDC*",
        "Dynatrace*",
        "oneagent*",
        "CommandLine",
        "Moq",
        "Castle.Core",
        "MiniProfiler*",
        "MySql*",
        "Serilog*",
        "ServiceStack*",
        "mscorlib",
        "Xunit.*",
        "xunit.*",
        "FluentAssertions",
        "NUnit3.TestAdapter",
        "nunit.*",
        "vstest.console",
        "testhost.*",
        "Oracle.ManagedDataAccess",
    };

    private static List<Regex>? _excludedAssembliesRegexes = null;

    private static bool _started = false;

    private static List<SecretRegex>? _secretRules = null;

    private static ManualResetEventSlim _waitEvent = new ManualResetEventSlim(false);

    public HardcodedSecretsAnalyzer()
    {
        LifetimeManager.Instance.AddShutdownTask(RunShutdown);

        if (_secretRules == null)
        {
            _secretRules = new List<SecretRegex>
            {
                new SecretRegex { Rule = "github-app-token", Regex = new Regex(@"(ghu|ghs)_[0-9a-zA-Z]{36}", RegexOptions.IgnoreCase | RegexOptions.Compiled) },
                new SecretRegex { Rule = "aws-access-token", Regex = new Regex(@"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", RegexOptions.IgnoreCase | RegexOptions.Compiled) },
            };
        }

        _started = true;
        Task.Run(() => PoolingThread());
    }

    private static void PoolingThread()
    {
        while (_started)
        {
            var userStrings = new UserStringInterop[100];
            int userStringLen = NativeMethods.GetUserStrings(userStrings.Length, userStrings);
            if (userStringLen > 0)
            {
                List<Vulnerability> vulnerabilities = new List<Vulnerability>();

                for (int x = 0; x < userStringLen; x++)
                {
                    var value = Marshal.PtrToStringUni(userStrings[x].Value);
                    var match = CheckSecret(value!);
                    if (!string.IsNullOrEmpty(match))
                    {
                        var location = Marshal.PtrToStringUni(userStrings[x].Location);
                        vulnerabilities.Add(new Vulnerability(
                            VulnerabilityTypeName.HardcodedSecret,
                            (VulnerabilityTypeName.HardcodedSecret + ":" + location!).GetStaticHashCode(),
                            new Location(location!),
                            new Evidence(match!),
                            IntegrationId.HardcodedSecret));
                    }
                }

                if (vulnerabilities.Count > 0)
                {
                    IastModule.OnHardcodedSecret(vulnerabilities);
                }

                if (userStringLen == userStrings.Length) { continue; }
            }

            _waitEvent.Wait(10_000);
        }
    }

    internal static string? CheckSecret(string secret)
    {
        if (_secretRules == null) { return null; }
        foreach (var rule in _secretRules)
        {
            if (rule.Regex.IsMatch(secret))
            {
                return rule.Rule;
            }
        }

        return null;
    }

    internal static void Initialize()
    {
        lock (Log)
        {
            if (_instance == null)
            {
                _instance = new HardcodedSecretsAnalyzer();
            }
        }
    }

    internal static bool IsExcluded(Assembly assembly)
    {
        if (_excludedAssembliesRegexes == null)
        {
            lock (Log)
            {
                if (_excludedAssembliesRegexes == null)
                {
                    _excludedAssembliesRegexes = new List<Regex>();

                    // Construct exclussion regexes
                    foreach (var txt in _excludedAssemblies)
                    {
                        var regex = new Regex(txt.Replace(".", "/.").Replace("*", ".*"), RegexOptions.IgnoreCase | RegexOptions.Compiled);
                        _excludedAssembliesRegexes.Add(regex);
                    }
                }
            }
        }

        if (assembly.IsDynamic) { return true; }

        foreach (var regex in _excludedAssembliesRegexes)
        {
            var name = assembly.GetName().Name;
            if (name == null || regex.IsMatch(name))
            {
                return true;
            }
        }

        return false;
    }

    private void RunShutdown()
    {
        try
        {
            _started = false;
            _waitEvent.Set();
        }
        catch { }
    }

    private struct SecretRegex
    {
        public string Rule;
        public Regex Regex;
    }
}
