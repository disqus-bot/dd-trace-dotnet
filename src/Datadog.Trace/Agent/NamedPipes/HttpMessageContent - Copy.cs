//------------------------------------------------------------------------------
// <auto-generated />
// This file was automatically generated by the UpdateVendors tool.
//------------------------------------------------------------------------------
// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#if !NET_4

using System.IO;
using System.Net.Http;
using Datadog.Trace.Agent.NamedPipes;

namespace Datadog.Trace.Agent.NamedPipes
{
    internal interface IHttpMessageSerializer
    {
        void Serialize(HttpResponseMessage response, Stream stream);
        void Serialize(HttpRequestMessage request, Stream stream);
        HttpResponseMessage DeserializeToResponse(Stream stream);
        HttpRequestMessage DeserializeToRequest(Stream stream);
    }

    internal class NamedPipeHttpMessageSerializer : IHttpMessageSerializer
    {
        private bool _bufferContent;

        public NamedPipeHttpMessageSerializer() : this(false)
        {

        }

        public NamedPipeHttpMessageSerializer(bool bufferContent)
        {
            _bufferContent = bufferContent;
        }


        public void Serialize(HttpResponseMessage response, Stream stream)
        {
            byte[] assuranceBuffer = null;
            if (_bufferContent && response.Content != null)
            {
                assuranceBuffer = response.Content.ReadAsByteArrayAsync().Result; // make sure it is buffered
            }

            var httpMessageContent = new NamedPipeHttpMessageContent(response);
            var buffer = httpMessageContent.ReadAsByteArrayAsync().Result;
            stream.Write(buffer, 0, buffer.Length);
        }

        public void Serialize(HttpRequestMessage request, Stream stream)
        {
            byte[] assuranceBuffer = null;
            if (_bufferContent && request.Content != null)
                assuranceBuffer = request.Content.ReadAsByteArrayAsync().Result; // make sure it is buffered

            var httpMessageContent = new NamedPipeHttpMessageContent(request);
            var buffer = httpMessageContent.ReadAsByteArrayAsync().Result;
            stream.Write(buffer, 0, buffer.Length);
        }

        public HttpResponseMessage DeserializeToResponse(Stream stream)
        {
            var response = new HttpResponseMessage();
            var memoryStream = new MemoryStream();
            stream.CopyTo(memoryStream);
            response.Content = new ByteArrayContent(memoryStream.ToArray());
            response.Content.Headers.Add("Content-Type", "application/http;msgtype=response");
            return response.Content.ReadAsHttpResponseMessageAsync().Result;
        }

        public HttpRequestMessage DeserializeToRequest(Stream stream)
        {
            var request = new HttpRequestMessage();
            var memoryStream = new MemoryStream();
            stream.CopyTo(memoryStream);
            request.Content = new ByteArrayContent(memoryStream.ToArray());
            request.Content.Headers.Add("Content-Type", "application/http;msgtype=request");
            return request.Content.ReadAsHttpRequestMessageAsync().Result;
        }
    }
}

#endif
