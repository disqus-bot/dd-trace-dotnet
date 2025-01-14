// <copyright file="UpdateResult.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

#nullable enable
using System;
using System.Collections.Generic;
using Datadog.Trace.Vendors.Newtonsoft.Json;

namespace Datadog.Trace.AppSec.Waf.ReturnTypes.Managed
{
    internal class UpdateResult
    {
        internal UpdateResult(Obj? diagObject, bool success, bool unusableRules = false)
        {
            if (diagObject != null)
            {
                var reportedDiag = DiagnosticResultUtils.ExtractReportedDiagnostics(diagObject, false);

                FailedToLoadRules = reportedDiag.FailedCount;
                LoadedRules = reportedDiag.LoadedCount;
                Errors = reportedDiag.Errors;
                RuleFileVersion = reportedDiag.RulesetVersion;

                if (Errors != null && Errors.Count > 0)
                {
                    HasErrors = true;
                    ErrorMessage = JsonConvert.SerializeObject(Errors);
                }
            }

            Success = success;
            UnusableRules = unusableRules;
        }

        internal bool Success { get; }

        internal bool UnusableRules { get; }

        internal ushort? FailedToLoadRules { get; }

        /// <summary>
        /// Gets the number of rules successfully loaded
        /// </summary>
        internal ushort? LoadedRules { get; }

        internal IReadOnlyDictionary<string, object>? Errors { get; }

        internal string? ErrorMessage { get; }

        internal bool HasErrors { get; }

        internal string? RuleFileVersion { get; }

        public static UpdateResult FromUnusableRules() => new UpdateResult(null, false, true);

        public static UpdateResult FromFailed() => new UpdateResult(null, false);
    }
}
