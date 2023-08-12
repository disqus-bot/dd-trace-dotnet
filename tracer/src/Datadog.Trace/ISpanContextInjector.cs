// <copyright file="ISpanContextInjector.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
using System.Collections.Generic;

#nullable enable

namespace Datadog.Trace
{
    /// <summary>
    /// The ISpanContextExtractor is responsible for extracting SpanContext in the rare cases where the Tracer couldn't propagate it itself.
    /// This can happen for instance when libraries add an extra layer above the instrumented ones
    /// (eg consuming Kafka messages and enqueuing them prior to generate a span).
    /// When enabled (and present in the headers) also used to set data streams monitoring checkpoints.
    /// </summary>
    public interface ISpanContextInjector
    {
        /// <summary>
        /// Given a SpanContext carrier and a function to set a value, this method will inject a SpanContext.
        /// You should only call <see cref="Inject{TCarrier}"/> once on the message <paramref name="carrier"/>. Calling
        /// multiple times may lead to incorrect behaviors.
        /// </summary>
        /// <param name="carrier">The carrier of the SpanContext. Often a header (http, kafka message header...)</param>
        /// <param name="setter">Given a key name and value, sets the value in the carrier</param>
        /// <param name="context">The context you want to inject</param>
        /// <typeparam name="TCarrier">Type of the carrier</typeparam>
        public void Inject<TCarrier>(TCarrier carrier, Action<TCarrier, string, string> setter, ISpanContext context);
    }
}
