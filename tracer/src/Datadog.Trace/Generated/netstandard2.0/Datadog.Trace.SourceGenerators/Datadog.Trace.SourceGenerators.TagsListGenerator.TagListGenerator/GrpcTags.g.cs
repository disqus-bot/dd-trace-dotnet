﻿// <auto-generated/>
#nullable enable

using Datadog.Trace.Processors;
using Datadog.Trace.Tagging;

namespace Datadog.Trace.Tagging
{
    partial class GrpcTags
    {
        // SpanKindBytes = System.Text.Encoding.UTF8.GetBytes("span.kind");
        private static readonly byte[] SpanKindBytes = new byte[] { 115, 112, 97, 110, 46, 107, 105, 110, 100 };
        // InstrumentationNameBytes = System.Text.Encoding.UTF8.GetBytes("component");
        private static readonly byte[] InstrumentationNameBytes = new byte[] { 99, 111, 109, 112, 111, 110, 101, 110, 116 };
        // MethodKindBytes = System.Text.Encoding.UTF8.GetBytes("rpc.grpc.kind");
        private static readonly byte[] MethodKindBytes = new byte[] { 114, 112, 99, 46, 103, 114, 112, 99, 46, 107, 105, 110, 100 };
        // MethodNameBytes = System.Text.Encoding.UTF8.GetBytes("rpc.method");
        private static readonly byte[] MethodNameBytes = new byte[] { 114, 112, 99, 46, 109, 101, 116, 104, 111, 100 };
        // MethodPathBytes = System.Text.Encoding.UTF8.GetBytes("rpc.grpc.path");
        private static readonly byte[] MethodPathBytes = new byte[] { 114, 112, 99, 46, 103, 114, 112, 99, 46, 112, 97, 116, 104 };
        // MethodPackageBytes = System.Text.Encoding.UTF8.GetBytes("rpc.grpc.package");
        private static readonly byte[] MethodPackageBytes = new byte[] { 114, 112, 99, 46, 103, 114, 112, 99, 46, 112, 97, 99, 107, 97, 103, 101 };
        // MethodServiceBytes = System.Text.Encoding.UTF8.GetBytes("rpc.service");
        private static readonly byte[] MethodServiceBytes = new byte[] { 114, 112, 99, 46, 115, 101, 114, 118, 105, 99, 101 };
        // StatusCodeBytes = System.Text.Encoding.UTF8.GetBytes("grpc.status.code");
        private static readonly byte[] StatusCodeBytes = new byte[] { 103, 114, 112, 99, 46, 115, 116, 97, 116, 117, 115, 46, 99, 111, 100, 101 };

        public override string? GetTag(string key)
        {
            return key switch
            {
                "span.kind" => SpanKind,
                "component" => InstrumentationName,
                "rpc.grpc.kind" => MethodKind,
                "rpc.method" => MethodName,
                "rpc.grpc.path" => MethodPath,
                "rpc.grpc.package" => MethodPackage,
                "rpc.service" => MethodService,
                "grpc.status.code" => StatusCode,
                _ => base.GetTag(key),
            };
        }

        public override void SetTag(string key, string value)
        {
            switch(key)
            {
                case "rpc.grpc.kind": 
                    MethodKind = value;
                    break;
                case "rpc.method": 
                    MethodName = value;
                    break;
                case "rpc.grpc.path": 
                    MethodPath = value;
                    break;
                case "rpc.grpc.package": 
                    MethodPackage = value;
                    break;
                case "rpc.service": 
                    MethodService = value;
                    break;
                case "grpc.status.code": 
                    StatusCode = value;
                    break;
                case "span.kind": 
                case "component": 
                    Logger.Value.Warning("Attempted to set readonly tag {TagName} on {TagType}. Ignoring.", key, nameof(GrpcTags));
                    break;
                default: 
                    base.SetTag(key, value);
                    break;
            }
        }

        public override void EnumerateTags<TProcessor>(ref TProcessor processor)
        {
            if (SpanKind is not null)
            {
                processor.Process(new TagItem<string>("span.kind", SpanKind, SpanKindBytes));
            }

            if (InstrumentationName is not null)
            {
                processor.Process(new TagItem<string>("component", InstrumentationName, InstrumentationNameBytes));
            }

            if (MethodKind is not null)
            {
                processor.Process(new TagItem<string>("rpc.grpc.kind", MethodKind, MethodKindBytes));
            }

            if (MethodName is not null)
            {
                processor.Process(new TagItem<string>("rpc.method", MethodName, MethodNameBytes));
            }

            if (MethodPath is not null)
            {
                processor.Process(new TagItem<string>("rpc.grpc.path", MethodPath, MethodPathBytes));
            }

            if (MethodPackage is not null)
            {
                processor.Process(new TagItem<string>("rpc.grpc.package", MethodPackage, MethodPackageBytes));
            }

            if (MethodService is not null)
            {
                processor.Process(new TagItem<string>("rpc.service", MethodService, MethodServiceBytes));
            }

            if (StatusCode is not null)
            {
                processor.Process(new TagItem<string>("grpc.status.code", StatusCode, StatusCodeBytes));
            }

            base.EnumerateTags(ref processor);
        }

        protected override void WriteAdditionalTags(System.Text.StringBuilder sb)
        {
            if (SpanKind is not null)
            {
                sb.Append("span.kind (tag):")
                  .Append(SpanKind)
                  .Append(',');
            }

            if (InstrumentationName is not null)
            {
                sb.Append("component (tag):")
                  .Append(InstrumentationName)
                  .Append(',');
            }

            if (MethodKind is not null)
            {
                sb.Append("rpc.grpc.kind (tag):")
                  .Append(MethodKind)
                  .Append(',');
            }

            if (MethodName is not null)
            {
                sb.Append("rpc.method (tag):")
                  .Append(MethodName)
                  .Append(',');
            }

            if (MethodPath is not null)
            {
                sb.Append("rpc.grpc.path (tag):")
                  .Append(MethodPath)
                  .Append(',');
            }

            if (MethodPackage is not null)
            {
                sb.Append("rpc.grpc.package (tag):")
                  .Append(MethodPackage)
                  .Append(',');
            }

            if (MethodService is not null)
            {
                sb.Append("rpc.service (tag):")
                  .Append(MethodService)
                  .Append(',');
            }

            if (StatusCode is not null)
            {
                sb.Append("grpc.status.code (tag):")
                  .Append(StatusCode)
                  .Append(',');
            }

            base.WriteAdditionalTags(sb);
        }
    }
}
