// <copyright file="ConfigurationKeys.Debugger.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using Datadog.Trace.Debugger;
using Datadog.Trace.Logging.DirectSubmission;

namespace Datadog.Trace.Configuration
{
    internal static partial class ConfigurationKeys
    {
        internal static class Debugger
        {
            /// <summary>
            /// Configuration key for debugger poll interval.
            /// </summary>
            /// <seealso cref="DebuggerSettings.ProbeConfigurationsPollIntervalSeconds"/>
            public const string PollInterval = "DD_DEBUGGER_POLL_INTERVAL";

            /// <summary>
            /// Configuration key for debugger agent mode.
            /// </summary>
            /// <seealso cref="DebuggerSettings.ProbeMode"/>
            public const string AgentMode = "DD_DEBUGGER_AGENT_MODE";

            /// <summary>
            /// Configuration key for the URL used to query our backend directly for the list of active probes.
            /// This can only be used if DD-API-KEY is also available.
            /// </summary>
            /// <seealso cref="DebuggerSettings.ProbeConfigurationsPath"/>
            public const string ProbeUrl = "DD_DEBUGGER_PROBE_URL";

            /// <summary>
            /// Configuration key for probe configuration file full path.
            /// Loads the probe configuration from a local file on disk. Useful for local development and testing.
            /// </summary>
            /// <seealso cref="DebuggerSettings.ProbeConfigurationsPath"/>
            public const string ProbeFile = "DD_DEBUGGER_PROBE_FILE";
        }
    }
}
