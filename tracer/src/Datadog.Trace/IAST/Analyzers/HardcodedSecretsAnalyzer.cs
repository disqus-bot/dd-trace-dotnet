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
    private static ManualResetEventSlim _waitEvent = new ManualResetEventSlim(false);

    public HardcodedSecretsAnalyzer()
    {
        LifetimeManager.Instance.AddShutdownTask(RunShutdown);

        // var assemblies = AppDomain.CurrentDomain.GetAssemblies();
        // AppDomain.CurrentDomain.AssemblyLoad += CurrentDomain_AssemblyLoad;
        // Task.Run(() => ProcessAssemblies(assemblies));

        _started = true;
        Task.Run(() => PoolingThread());
    }

    private static void PoolingThread()
    {
        while (_started)
        {
            var waf = Security.Instance.WafInitResult?.Waf;
            if (waf != null)
            {
                var timeout = Security.Instance.Settings.WafTimeoutMicroSeconds;
                var userStrings = new UserStringInterop[100];
                int userStringLen = NativeMethods.GetUserStrings(userStrings.Length, userStrings);
                if (userStringLen > 0)
                {
                    List<Vulnerability> vulnerabilities = new List<Vulnerability>();

                    for (int x = 0; x < userStringLen; x++)
                    {
                        using var context = waf.CreateContext();
                        if (context != null)
                        {
                            var value = Marshal.PtrToStringUni(userStrings[x].Value);
                            if (CheckSecret(context!, value!, timeout))
                            {
                                var location = Marshal.PtrToStringUni(userStrings[x].Location);
                                vulnerabilities.Add(new Vulnerability(
                                    VulnerabilityTypeName.HardcodedSecret,
                                    (VulnerabilityTypeName.HardcodedSecret + ":" + location! + ":" + value!).GetStaticHashCode(),
                                    new Location(location!),
                                    new Evidence(value!),
                                    IntegrationId.HardcodedSecret));
                            }
                        }
                    }

                    if (vulnerabilities.Count > 0)
                    {
                        IastModule.OnHardcodedSecret(vulnerabilities);
                    }
                }
            }

            _waitEvent.Wait(10_000);
        }
    }

    private void CurrentDomain_AssemblyLoad(object? sender, AssemblyLoadEventArgs args)
    {
        Task.Run(() => ProcessAssemblies(args.LoadedAssembly));
    }

    internal void ProcessAssemblies(params Assembly[] assemblies)
    {
        var waf = Security.Instance.WafInitResult?.Waf;
        if (waf != null)
        {
            foreach (var assembly in assemblies)
            {
                if (IsExcluded(assembly)) { continue; }
                var secrets = ProcessAssembly(waf, Security.Instance.Settings.WafTimeoutMicroSeconds, assembly);
                if (secrets.Count > 0)
                {
                    List<Vulnerability> vulnerabilities = new List<Vulnerability>();
                    var location = assembly.Location;
                    foreach (var secret in secrets)
                    {
                        vulnerabilities.Add(new Vulnerability(
                            VulnerabilityTypeName.HardcodedSecret,
                            (VulnerabilityTypeName.HardcodedSecret + ":" + location + ":" + secret).GetStaticHashCode(),
                            new Location(location),
                            new Evidence(secret),
                            IntegrationId.HardcodedSecret));
                    }

                    IastModule.OnHardcodedSecret(vulnerabilities);
                }
            }
        }
    }

    private static List<string> ProcessAssembly(IWaf waf, ulong timeout, Assembly assembly)
    {
        List<string> res = new List<string>();
        try
        {
            using var fs = new FileStream(assembly.Location, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var peReader = new PEReader(fs);
            MetadataReader mr = peReader.GetMetadataReader();

            UserStringHandle userStringHandle = mr.GetNextHandle(new UserStringHandle());
            while (!userStringHandle.IsNil)
            {
                var userString = mr.GetUserString(userStringHandle);
                using var context = waf.CreateContext();
                if (context != null)
                {
                    if (CheckSecret(context, userString, timeout))
                    {
                        res.Add(userString);
                    }
                }

                userStringHandle = mr.GetNextHandle(userStringHandle);
            }
        }
        catch (Exception err)
        {
            Log.Warning(err, "Error processing assembly {0}", assembly);
        }

        return res;
    }

    internal static bool CheckSecret(IContext context, string secret, ulong timeout)
    {
        var args = new Dictionary<string, object> { { "hardcoded.secret", secret } };

        var result = context.Run(args, timeout);
        return (result != null && result.ReturnCode == ReturnCode.Match);
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
            AppDomain.CurrentDomain.AssemblyLoad -= CurrentDomain_AssemblyLoad;
        }
        catch { }
    }
}
