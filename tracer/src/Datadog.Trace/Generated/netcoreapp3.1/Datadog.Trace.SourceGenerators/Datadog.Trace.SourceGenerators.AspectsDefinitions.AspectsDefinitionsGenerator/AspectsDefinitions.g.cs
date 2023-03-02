﻿// <auto-generated/>
#nullable enable

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Datadog.Trace.ClrProfiler
{
    internal static partial class AspectDefinitions
    {
        public static string[] Aspects = new string[] {
"[AspectClass(\"mscorlib,netstandard,System.Private.CoreLib\",[StringOptimization],Propagation,[])] Datadog.Trace.Iast.Aspects.System.StringAspects",
"  [AspectMethodReplace(\"System.String::Concat(System.String,System.String)\",\"\",[0],[False],[StringLiterals_Any],Propagation,[])] Concat(System.String,System.String)",
"  [AspectMethodReplace(\"System.String::Concat(System.String,System.String)\",\"\",[0],[False],[StringLiteral_0],Propagation,[])] Concat_0(System.String,System.String)",
"  [AspectMethodReplace(\"System.String::Concat(System.String,System.String)\",\"\",[0],[False],[StringLiteral_1],Propagation,[])] Concat_1(System.String,System.String)",
"  [AspectMethodReplace(\"System.String::Concat(System.Object,System.Object)\",\"\",[0],[False],[None],Propagation,[])] Concat(System.Object,System.Object)",
"  [AspectMethodReplace(\"System.String::Concat(System.String,System.String,System.String)\",\"\",[0],[False],[StringLiterals],Propagation,[])] Concat(System.String,System.String,System.String)",
"  [AspectMethodReplace(\"System.String::Concat(System.Object,System.Object,System.Object)\",\"\",[0],[False],[None],Propagation,[])] Concat(System.Object,System.Object,System.Object)",
"  [AspectMethodReplace(\"System.String::Concat(System.String,System.String,System.String,System.String)\",\"\",[0],[False],[StringLiterals],Propagation,[])] Concat(System.String,System.String,System.String,System.String)",
"  [AspectMethodReplace(\"System.String::Concat(System.Object,System.Object,System.Object,System.Object)\",\"\",[0],[False],[None],Propagation,[])] Concat(System.Object,System.Object,System.Object,System.Object)",
"  [AspectMethodReplace(\"System.String::Concat(System.String,System.String,System.String,System.String,System.String)\",\"\",[0],[False],[StringLiterals],Propagation,[])] Concat(System.String,System.String,System.String,System.String,System.String)",
"  [AspectMethodReplace(\"System.String::Concat(System.Object,System.Object,System.Object,System.Object,System.Object)\",\"\",[0],[False],[None],Propagation,[])] Concat(System.Object,System.Object,System.Object,System.Object,System.Object)",
"  [AspectMethodReplace(\"System.String::Concat(System.String[])\",\"\",[0],[False],[None],Propagation,[])] Concat(System.String[])",
"  [AspectMethodReplace(\"System.String::Concat(System.Object[])\",\"\",[0],[False],[None],Propagation,[])] Concat(System.Object[])",
"  [AspectMethodReplace(\"System.String::Concat(System.Collections.Generic.IEnumerable`1<System.String>)\",\"\",[0],[False],[None],Propagation,[])] Concat(System.Collections.IEnumerable)",
"  [AspectMethodReplace(\"System.String::Concat(System.Collections.Generic.IEnumerable`1<!!0>)\",\"\",[0],[False],[None],Propagation,[])] Concat2(System.Collections.IEnumerable)",
        };
    }
}
