// <copyright file="ServiceBusSenderConstructorIntegration.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
using System.ComponentModel;
using Datadog.Trace.ClrProfiler.CallTarget;
using Datadog.Trace.Configuration;
using Datadog.Trace.DuckTyping;

namespace Datadog.Trace.ClrProfiler.AutoInstrumentation.Azure.ServiceBus;

/// <summary>
/// Confluent.Kafka Consumer() calltarget instrumentation
/// </summary>
[InstrumentMethod(
    AssemblyName = "Azure.Messaging.ServiceBus",
    TypeName = "Azure.Messaging.ServiceBus.ServiceBusSender",
    MethodName = ".ctor",
    ReturnTypeName = ClrNames.Void,
    ParameterTypeNames = new[] { ClrNames.String, "Azure.Messaging.ServiceBus.ServiceBusConnection", "Azure.Messaging.ServiceBus.ServiceBusSenderOptions" },
    MinimumVersion = "7.14.0",
    MaximumVersion = "7.*.*",
    IntegrationName = nameof(IntegrationId.AzureServiceBus))]
[Browsable(false)]
[EditorBrowsable(EditorBrowsableState.Never)]
public class ServiceBusSenderConstructorIntegration
{
    internal static CallTargetState OnMethodBegin<TTarget, TServiceBusConnection, TServiceBusSenderOptions>(TTarget instance, string entityPath, TServiceBusConnection connection, TServiceBusSenderOptions options)
        where TServiceBusConnection : IServiceBusConnection, IDuckType
    {
        if (Tracer.Instance.Settings.IsIntegrationEnabled(IntegrationId.AzureServiceBus)
            && connection.Instance is not null)
        {
            return new CallTargetState(scope: null, state: connection.FullyQualifiedNamespace);
        }

        return CallTargetState.GetDefault();
    }

    internal static CallTargetReturn OnMethodEnd<TTarget>(TTarget instance, Exception exception, in CallTargetState state)
        where TTarget : IServiceBusSender
    {
        // This method is called in the ServiceBusSender constructor, so if we have an exception
        // the sender won't be created, so no point recording it.
        if (exception is null && state.State is string s)
        {
            TransportSenderHelper.SetFullyQualifiedNamespace(instance.InnerSender, s);
        }

        return CallTargetReturn.GetDefault();
    }
}
