// <copyright file="HttpTransport.Core.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

#if !NETFRAMEWORK
using System;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace.AppSec.Waf;
using Datadog.Trace.Headers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Datadog.Trace.AppSec.Transports.Http
{
    internal class HttpTransport : ITransport
    {
        private readonly HttpContext _context;

        public HttpTransport(HttpContext context) => _context = context;

        public bool IsSecureConnection => _context.Request.IsHttps;

        public bool Blocked => _context.Items["block"] is bool blocked && blocked;

        public Func<string, string> GetHeader => key => _context.Request.Headers[key];

        public IContext GetAdditiveContext()
        {
            return _context.Features.Get<IContext>();
        }

        public void DisposeAdditiveContext() => GetAdditiveContext()?.Dispose();

        public void SetAdditiveContext(IContext additive_context)
        {
            _context.Features.Set(additive_context);
        }

        public IHeadersCollection GetRequestHeaders()
        {
            return new HeadersCollectionAdapter(_context.Request.Headers);
        }

        public IHeadersCollection GetResponseHeaders()
        {
            return new HeadersCollectionAdapter(_context.Response.Headers);
        }

        public void WriteBlockedResponse(string templateJson, string templateHtml, bool canAccessHeaders)
        {
            _context.Items["block"] = true;
        }
    }
}
#endif
