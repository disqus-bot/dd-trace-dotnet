﻿// <auto-generated/>
#nullable enable

using Datadog.Trace.Processors;
using Datadog.Trace.Tagging;

namespace Datadog.Trace.Tagging
{
    partial class GrpcClientTags
    {
        // MeasuredBytes = System.Text.Encoding.UTF8.GetBytes("_dd.measured");
        private static readonly byte[] MeasuredBytes = new byte[] { 95, 100, 100, 46, 109, 101, 97, 115, 117, 114, 101, 100 };

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
                    Logger.Value.Warning("Attempted to set readonly metric {MetricName} on {TagType}. Ignoring.", key, nameof(GrpcClientTags));
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
