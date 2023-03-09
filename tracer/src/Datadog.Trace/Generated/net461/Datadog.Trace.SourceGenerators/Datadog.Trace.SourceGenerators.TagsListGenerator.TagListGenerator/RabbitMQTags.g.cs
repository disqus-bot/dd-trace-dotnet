﻿// <auto-generated/>
#nullable enable

using Datadog.Trace.Processors;
using Datadog.Trace.Tagging;

namespace Datadog.Trace.Tagging
{
    partial class RabbitMQTags
    {
        // SpanKindBytes = System.Text.Encoding.UTF8.GetBytes("span.kind");
        private static readonly byte[] SpanKindBytes = new byte[] { 115, 112, 97, 110, 46, 107, 105, 110, 100 };
        // InstrumentationNameBytes = System.Text.Encoding.UTF8.GetBytes("component");
        private static readonly byte[] InstrumentationNameBytes = new byte[] { 99, 111, 109, 112, 111, 110, 101, 110, 116 };
        // CommandBytes = System.Text.Encoding.UTF8.GetBytes("messaging.operation");
        private static readonly byte[] CommandBytes = new byte[] { 109, 101, 115, 115, 97, 103, 105, 110, 103, 46, 111, 112, 101, 114, 97, 116, 105, 111, 110 };
        // DeliveryModeBytes = System.Text.Encoding.UTF8.GetBytes("messaging.rabbitmq.delivery_mode");
        private static readonly byte[] DeliveryModeBytes = new byte[] { 109, 101, 115, 115, 97, 103, 105, 110, 103, 46, 114, 97, 98, 98, 105, 116, 109, 113, 46, 100, 101, 108, 105, 118, 101, 114, 121, 95, 109, 111, 100, 101 };
        // ExchangeBytes = System.Text.Encoding.UTF8.GetBytes("messaging.rabbitmq.exchange");
        private static readonly byte[] ExchangeBytes = new byte[] { 109, 101, 115, 115, 97, 103, 105, 110, 103, 46, 114, 97, 98, 98, 105, 116, 109, 113, 46, 101, 120, 99, 104, 97, 110, 103, 101 };
        // RoutingKeyBytes = System.Text.Encoding.UTF8.GetBytes("messaging.rabbitmq.routing_key");
        private static readonly byte[] RoutingKeyBytes = new byte[] { 109, 101, 115, 115, 97, 103, 105, 110, 103, 46, 114, 97, 98, 98, 105, 116, 109, 113, 46, 114, 111, 117, 116, 105, 110, 103, 95, 107, 101, 121 };
        // MessageSizeBytes = System.Text.Encoding.UTF8.GetBytes("message.size");
        private static readonly byte[] MessageSizeBytes = new byte[] { 109, 101, 115, 115, 97, 103, 101, 46, 115, 105, 122, 101 };
        // QueueBytes = System.Text.Encoding.UTF8.GetBytes("messaging.destination");
        private static readonly byte[] QueueBytes = new byte[] { 109, 101, 115, 115, 97, 103, 105, 110, 103, 46, 100, 101, 115, 116, 105, 110, 97, 116, 105, 111, 110 };

        public override string? GetTag(string key)
        {
            return key switch
            {
                "span.kind" => SpanKind,
                "component" => InstrumentationName,
                "messaging.operation" => Command,
                "messaging.rabbitmq.delivery_mode" => DeliveryMode,
                "messaging.rabbitmq.exchange" => Exchange,
                "messaging.rabbitmq.routing_key" => RoutingKey,
                "message.size" => MessageSize,
                "messaging.destination" => Queue,
                _ => base.GetTag(key),
            };
        }

        public override void SetTag(string key, string value)
        {
            switch(key)
            {
                case "component": 
                    InstrumentationName = value;
                    break;
                case "messaging.operation": 
                    Command = value;
                    break;
                case "messaging.rabbitmq.delivery_mode": 
                    DeliveryMode = value;
                    break;
                case "messaging.rabbitmq.exchange": 
                    Exchange = value;
                    break;
                case "messaging.rabbitmq.routing_key": 
                    RoutingKey = value;
                    break;
                case "message.size": 
                    MessageSize = value;
                    break;
                case "messaging.destination": 
                    Queue = value;
                    break;
                case "span.kind": 
                    Logger.Value.Warning("Attempted to set readonly tag {TagName} on {TagType}. Ignoring.", key, nameof(RabbitMQTags));
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

            if (Command is not null)
            {
                processor.Process(new TagItem<string>("messaging.operation", Command, CommandBytes));
            }

            if (DeliveryMode is not null)
            {
                processor.Process(new TagItem<string>("messaging.rabbitmq.delivery_mode", DeliveryMode, DeliveryModeBytes));
            }

            if (Exchange is not null)
            {
                processor.Process(new TagItem<string>("messaging.rabbitmq.exchange", Exchange, ExchangeBytes));
            }

            if (RoutingKey is not null)
            {
                processor.Process(new TagItem<string>("messaging.rabbitmq.routing_key", RoutingKey, RoutingKeyBytes));
            }

            if (MessageSize is not null)
            {
                processor.Process(new TagItem<string>("message.size", MessageSize, MessageSizeBytes));
            }

            if (Queue is not null)
            {
                processor.Process(new TagItem<string>("messaging.destination", Queue, QueueBytes));
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

            if (Command is not null)
            {
                sb.Append("messaging.operation (tag):")
                  .Append(Command)
                  .Append(',');
            }

            if (DeliveryMode is not null)
            {
                sb.Append("messaging.rabbitmq.delivery_mode (tag):")
                  .Append(DeliveryMode)
                  .Append(',');
            }

            if (Exchange is not null)
            {
                sb.Append("messaging.rabbitmq.exchange (tag):")
                  .Append(Exchange)
                  .Append(',');
            }

            if (RoutingKey is not null)
            {
                sb.Append("messaging.rabbitmq.routing_key (tag):")
                  .Append(RoutingKey)
                  .Append(',');
            }

            if (MessageSize is not null)
            {
                sb.Append("message.size (tag):")
                  .Append(MessageSize)
                  .Append(',');
            }

            if (Queue is not null)
            {
                sb.Append("messaging.destination (tag):")
                  .Append(Queue)
                  .Append(',');
            }

            base.WriteAdditionalTags(sb);
        }
    }
}
