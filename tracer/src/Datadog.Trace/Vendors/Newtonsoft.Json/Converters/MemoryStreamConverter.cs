// <copyright file="MemoryStreamConverter.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

using System;
using System.IO;
using System.Text;

namespace Datadog.Trace.Vendors.Newtonsoft.Json.Converters;

internal class MemoryStreamConverter : JsonConverter<MemoryStream>
{
    public override void WriteJson(JsonWriter writer, MemoryStream value, JsonSerializer serializer)
    {
        value.Position = 0;
        var firstBytes = new byte[1];
        value.Read(firstBytes);

        if (firstBytes.Length > 0 && firstBytes[0] == '{')
        {
            // assume it's json, serialize it as a string value
            value.Position = 0;
            var reader = new StreamReader(value, Encoding.UTF8, leaveOpen: true);
            string json = reader.ReadToEnd();
            value.Position = 0;
            writer.WriteValue(json);
        }
        else
        {
            writer.WriteValue("<binary data>");
        }
    }

    public override MemoryStream ReadJson(JsonReader reader, Type objectType, MemoryStream existingValue, bool hasExistingValue, JsonSerializer serializer)
    {
        throw new NotImplementedException();
    }
}
