﻿// <auto-generated/>
#nullable enable

using Datadog.Trace.Processors;
using Datadog.Trace.Tagging;

namespace Datadog.Trace.Tagging
{
    partial class AerospikeTags
    {
        // MeasuredBytes = System.Text.Encoding.UTF8.GetBytes("_dd.measured");
        private static readonly byte[] MeasuredBytes = new byte[] { 95, 100, 100, 46, 109, 101, 97, 115, 117, 114, 101, 100 };
        // SpanKindBytes = System.Text.Encoding.UTF8.GetBytes("span.kind");
        private static readonly byte[] SpanKindBytes = new byte[] { 115, 112, 97, 110, 46, 107, 105, 110, 100 };
        // InstrumentationNameBytes = System.Text.Encoding.UTF8.GetBytes("component");
        private static readonly byte[] InstrumentationNameBytes = new byte[] { 99, 111, 109, 112, 111, 110, 101, 110, 116 };
        // KeyBytes = System.Text.Encoding.UTF8.GetBytes("aerospike.key");
        private static readonly byte[] KeyBytes = new byte[] { 97, 101, 114, 111, 115, 112, 105, 107, 101, 46, 107, 101, 121 };
        // NamespaceBytes = System.Text.Encoding.UTF8.GetBytes("aerospike.namespace");
        private static readonly byte[] NamespaceBytes = new byte[] { 97, 101, 114, 111, 115, 112, 105, 107, 101, 46, 110, 97, 109, 101, 115, 112, 97, 99, 101 };
        // SetNameBytes = System.Text.Encoding.UTF8.GetBytes("aerospike.setname");
        private static readonly byte[] SetNameBytes = new byte[] { 97, 101, 114, 111, 115, 112, 105, 107, 101, 46, 115, 101, 116, 110, 97, 109, 101 };
        // UserKeyBytes = System.Text.Encoding.UTF8.GetBytes("aerospike.userkey");
        private static readonly byte[] UserKeyBytes = new byte[] { 97, 101, 114, 111, 115, 112, 105, 107, 101, 46, 117, 115, 101, 114, 107, 101, 121 };

        public override string? GetTag(string key)
        {
            return key switch
            {
                "span.kind" => SpanKind,
                "component" => InstrumentationName,
                "aerospike.key" => Key,
                "aerospike.namespace" => Namespace,
                "aerospike.setname" => SetName,
                "aerospike.userkey" => UserKey,
                _ => base.GetTag(key),
            };
        }

        public override void SetTag(string key, string value)
        {
            switch(key)
            {
                case "aerospike.key": 
                    Key = value;
                    break;
                case "aerospike.namespace": 
                    Namespace = value;
                    break;
                case "aerospike.setname": 
                    SetName = value;
                    break;
                case "aerospike.userkey": 
                    UserKey = value;
                    break;
                case "span.kind": 
                case "component": 
                    Logger.Value.Warning("Attempted to set readonly tag {TagName} on {TagType}. Ignoring.", key, nameof(AerospikeTags));
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

            if (Key is not null)
            {
                processor.Process(new TagItem<string>("aerospike.key", Key, KeyBytes));
            }

            if (Namespace is not null)
            {
                processor.Process(new TagItem<string>("aerospike.namespace", Namespace, NamespaceBytes));
            }

            if (SetName is not null)
            {
                processor.Process(new TagItem<string>("aerospike.setname", SetName, SetNameBytes));
            }

            if (UserKey is not null)
            {
                processor.Process(new TagItem<string>("aerospike.userkey", UserKey, UserKeyBytes));
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

            if (Key is not null)
            {
                sb.Append("aerospike.key (tag):")
                  .Append(Key)
                  .Append(',');
            }

            if (Namespace is not null)
            {
                sb.Append("aerospike.namespace (tag):")
                  .Append(Namespace)
                  .Append(',');
            }

            if (SetName is not null)
            {
                sb.Append("aerospike.setname (tag):")
                  .Append(SetName)
                  .Append(',');
            }

            if (UserKey is not null)
            {
                sb.Append("aerospike.userkey (tag):")
                  .Append(UserKey)
                  .Append(',');
            }

            base.WriteAdditionalTags(sb);
        }
        public override double? GetMetric(string key)
        {
            return key switch
            {
                "_dd.measured" => Measured,
                _ => base.GetMetric(key),
            };
        }

        public override void SetMetric(string key, double? value)
        {
            switch(key)
            {
                case "_dd.measured": 
                    Logger.Value.Warning("Attempted to set readonly metric {MetricName} on {TagType}. Ignoring.", key, nameof(AerospikeTags));
                    break;
                default: 
                    base.SetMetric(key, value);
                    break;
            }
        }

        public override void EnumerateMetrics<TProcessor>(ref TProcessor processor)
        {
            if (Measured is not null)
            {
                processor.Process(new TagItem<double>("_dd.measured", Measured.Value, MeasuredBytes));
            }

            base.EnumerateMetrics(ref processor);
        }

        protected override void WriteAdditionalMetrics(System.Text.StringBuilder sb)
        {
            if (Measured is not null)
            {
                sb.Append("_dd.measured (metric):")
                  .Append(Measured.Value)
                  .Append(',');
            }

            base.WriteAdditionalMetrics(sb);
        }
    }
}
