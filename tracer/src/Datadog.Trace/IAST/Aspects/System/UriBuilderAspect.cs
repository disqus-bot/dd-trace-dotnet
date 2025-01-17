// <copyright file="UriBuilderAspect.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
using Datadog.Trace.Iast.Dataflow;
using Datadog.Trace.Iast.Propagation;

#nullable enable

namespace Datadog.Trace.Iast.Aspects.System;

/// <summary> UriBuilder class aspects </summary>
[AspectClass("System,netstandard,System.Runtime.Extensions,System.Runtime")]
[global::System.ComponentModel.Browsable(false)]
[global::System.ComponentModel.EditorBrowsable(global::System.ComponentModel.EditorBrowsableState.Never)]
public class UriBuilderAspect
{
    /// <summary>
    /// Taints the UriBuilder if the input parameters are tainted
    /// </summary>
    /// <param name="uriText">the uri</param>
    /// <returns>the result of the original method</returns>
    [AspectCtorReplace("System.UriBuilder::.ctor(System.String)", AspectFilter.StringLiteral_1)]
    public static UriBuilder Init(string uriText)
    {
        var result = new UriBuilder(uriText);
        PropagationModuleImpl.PropagateResultWhenInputTainted(result.Uri.OriginalString, uriText);
        return result;
    }

    /// <summary>
    /// Taints the UriBuilder if the input parameters are tainted
    /// </summary>
    /// <param name="uri">the uri</param>
    /// <returns>the result of the original method</returns>
    [AspectCtorReplace("System.UriBuilder::.ctor(System.Uri)")]
    public static UriBuilder Init(Uri uri)
    {
        var result = new UriBuilder(uri);
        PropagationModuleImpl.PropagateResultWhenInputTainted(result.Uri.OriginalString, uri.OriginalString);
        return result;
    }

    /// <summary>
    /// Taints the UriBuilder if the sensitive input parameters are tainted
    /// </summary>
    /// <param name="scheme">the scheme</param>
    /// <param name="host">the host</param>
    /// <returns>the result of the original method</returns>
    [AspectCtorReplace("System.UriBuilder::.ctor(System.String,System.String)")]
    public static UriBuilder Init(string scheme, string host)
    {
        var result = new UriBuilder(scheme, host);
        PropagationModuleImpl.PropagateResultWhenInputTainted(result.Uri.OriginalString, host);
        return result;
    }

    /// <summary>
    /// Taints the UriBuilder if the sensitive input parameters are tainted
    /// </summary>
    /// <param name="scheme">the scheme</param>
    /// <param name="host">the host</param>
    /// <param name="port">the port</param>
    /// <returns>the result of the original method</returns>
    [AspectCtorReplace("System.UriBuilder::.ctor(System.String,System.String,System.Int32)")]
    public static UriBuilder Init(string scheme, string host, int port)
    {
        var result = new UriBuilder(scheme, host, port);
        PropagationModuleImpl.PropagateResultWhenInputTainted(result.Uri.OriginalString, host);
        return result;
    }

    /// <summary>
    /// Taints the UriBuilder if the sensitive input parameters are tainted
    /// </summary>
    /// <param name="scheme">the scheme</param>
    /// <param name="host">the host</param>
    /// <param name="port">the port</param>
    /// <param name="path">the path</param>
    /// <returns>the result of the original method</returns>
    [AspectCtorReplace("System.UriBuilder::.ctor(System.String,System.String,System.Int32,System.String)")]
    public static UriBuilder Init(string scheme, string host, int port, string path)
    {
        var result = new UriBuilder(scheme, host, port, path);
        PropagationModuleImpl.PropagateResultWhenInputTainted(result.Uri.OriginalString, host, path);
        return result;
    }

    /// <summary>
    /// Taints the UriBuilder if the sensitive input parameters are tainted
    /// </summary>
    /// <param name="scheme">the scheme</param>
    /// <param name="host">the host</param>
    /// <param name="port">the port</param>
    /// <param name="path">the path</param>
    /// <param name="extra">the extra parameter</param>
    /// <returns>the result of the original method</returns>
    [AspectCtorReplace("System.UriBuilder::.ctor(System.String,System.String,System.Int32,System.String,System.String)")]
    public static UriBuilder Init(string scheme, string host, int port, string path, string extra)
    {
        var result = new UriBuilder(scheme, host, port, path, extra);
        PropagationModuleImpl.PropagateResultWhenInputTainted(result.Uri.OriginalString, host, path, extra);
        return result;
    }

    /// <summary>
    /// Uri SetHost aspect.
    /// </summary>
    /// <param name="instance">The UriBuilder instance.</param>
    /// <param name="parameter">The parameter value.</param>
    [AspectMethodReplace("System.UriBuilder::set_Host(System.String)", AspectFilter.StringLiteral_1)]
    public static void SetHost(UriBuilder instance, string parameter)
    {
        instance.Host = parameter;
        PropagationModuleImpl.PropagateResultWhenInputTainted(instance.Uri.OriginalString, parameter);
    }

    /// <summary>
    /// Uri set_Query aspect.
    /// </summary>
    /// <param name="instance">The UriBuilder instance.</param>
    /// <param name="parameter">The parameter value.</param>
    [AspectMethodReplace("System.UriBuilder::set_Query(System.String)", AspectFilter.StringLiteral_1)]
    public static void SetQuery(UriBuilder instance, string parameter)
    {
        instance.Query = parameter;
        PropagationModuleImpl.PropagateResultWhenInputTainted(instance.Uri.OriginalString, parameter);
    }

    /// <summary>
    /// Uri set_Path aspect.
    /// </summary>
    /// <param name="instance">The UriBuilder instance.</param>
    /// <param name="parameter">The parameter value.</param>
    [AspectMethodReplace("System.UriBuilder::set_Path(System.String)", AspectFilter.StringLiteral_1)]
    public static void SetPath(UriBuilder instance, string parameter)
    {
        instance.Path = parameter;
        PropagationModuleImpl.PropagateResultWhenInputTainted(instance.Uri.OriginalString, parameter);
    }

    /// <summary>
    /// Uri GetHost aspect.
    /// </summary>
    /// <param name="instance">The UriBuilder instance.</param>
    /// <returns>The host propoerty of the UriBuilder.</returns>
    [AspectMethodReplace("System.UriBuilder::get_Host()")]
    public static string GetHost(UriBuilder instance)
    {
        var result = instance.Host;
        PropagationModuleImpl.PropagateResultWhenInputTainted(result, instance.Uri.OriginalString);
        return result;
    }

    /// <summary>
    /// Uri GetHost aspect.
    /// </summary>
    /// <param name="instance">The UriBuilder instance.</param>
    /// <returns>The host propoerty of the UriBuilder.</returns>
    [AspectMethodReplace("System.UriBuilder::get_Query()")]
    public static string GetQuery(UriBuilder instance)
    {
        var result = instance.Query;
        PropagationModuleImpl.PropagateResultWhenInputTainted(result, instance.Uri.OriginalString);
        return result;
    }

    /// <summary>
    /// Uri GetHost aspect.
    /// </summary>
    /// <param name="instance">The UriBuilder instance.</param>
    /// <returns>The host propoerty of the UriBuilder.</returns>
    [AspectMethodReplace("System.UriBuilder::get_Path()")]
    public static string GetPath(UriBuilder instance)
    {
        var result = instance.Path;
        PropagationModuleImpl.PropagateResultWhenInputTainted(result, instance.Uri.OriginalString);
        return result;
    }

    /// <summary>
    /// Taints the UriBuilder if the instance is tainted
    /// </summary>
    /// <param name="instance">the UriBuilder instance</param>
    /// <returns>the result of the original method</returns>
    [AspectMethodReplace("System.Object::ToString()", "System.UriBuilder")]
    public static string? ToString(object? instance)
    {
        // We want the null reference exception to be launched here if target is null
        var result = instance!.ToString();
        PropagationModuleImpl.PropagateResultWhenInputTainted(result, (instance as UriBuilder)?.Uri?.OriginalString);
        return result;
    }
}
