// <copyright file="TransportSenderHelper.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

#nullable enable

using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Datadog.Trace.ClrProfiler.AutoInstrumentation.Azure.ServiceBus
{
    internal class TransportSenderHelper
    {
        // A map between Kafka Consumer<TKey,TValue> and the corresponding consumer group
        private static readonly ConditionalWeakTable<object, string> TransportSenderToFullyQualifiedNamespaceMap = new();

        public static void SetFullyQualifiedNamespace(object transportSender, string fullyQualifiedNamespace)
        {
#if NETCOREAPP3_1_OR_GREATER
            TransportSenderToFullyQualifiedNamespaceMap.AddOrUpdate(transportSender, fullyQualifiedNamespace);
#else
        TransportSenderToFullyQualifiedNamespaceMap.GetValue(transportSender, x => fullyQualifiedNamespace);
#endif
        }

        public static bool TryGetFullyQualifiedNamespace(object transportSender, out string? fullyQualifiedNamespace)
            => TransportSenderToFullyQualifiedNamespaceMap.TryGetValue(transportSender, out fullyQualifiedNamespace);

        public static bool RemoveFullyQualifiedNamespace(object transportSender)
            => TransportSenderToFullyQualifiedNamespaceMap.Remove(transportSender);
    }
}
