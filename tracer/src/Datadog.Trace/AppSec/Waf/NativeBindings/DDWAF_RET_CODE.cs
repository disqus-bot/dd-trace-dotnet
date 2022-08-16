// <copyright file="DDWAF_RET_CODE.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
using System.Collections.Generic;
using System.Text;

namespace Datadog.Trace.AppSec.Waf.NativeBindings
{
    internal enum DDWAF_RET_CODE
    {
        DDWAF_ERR_INTERNAL = -3,
        DDWAF_ERR_INVALID_OBJECT = -2,
        DDWAF_ERR_INVALID_ARGUMENT = -1,
        DDWAF_OK = 0,
        DDWAF_MATCH = 1,
        DDWAF_BLOCK = 2
    }
}
