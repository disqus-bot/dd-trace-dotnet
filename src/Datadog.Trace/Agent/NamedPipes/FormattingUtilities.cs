//------------------------------------------------------------------------------
// <auto-generated />
// This file was automatically generated by the UpdateVendors tool.
//------------------------------------------------------------------------------
// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Runtime.Serialization;
using System.Xml;

namespace Datadog.Trace.Agent.NamedPipes
{
    /// <summary>
    /// Provides various internal utility functions
    /// </summary>
    internal static class FormattingUtilities
    {
        // Supported date formats for input.
        private static readonly string[] dateFormats = new string[]
        {
            // "r", // RFC 1123, required output format but too strict for input
            "ddd, d MMM yyyy H:m:s 'GMT'", // RFC 1123 (r, except it allows both 1 and 01 for date and time)
            "ddd, d MMM yyyy H:m:s", // RFC 1123, no zone - assume GMT
            "d MMM yyyy H:m:s 'GMT'", // RFC 1123, no day-of-week
            "d MMM yyyy H:m:s", // RFC 1123, no day-of-week, no zone
            "ddd, d MMM yy H:m:s 'GMT'", // RFC 1123, short year
            "ddd, d MMM yy H:m:s", // RFC 1123, short year, no zone
            "d MMM yy H:m:s 'GMT'", // RFC 1123, no day-of-week, short year
            "d MMM yy H:m:s", // RFC 1123, no day-of-week, short year, no zone

            "dddd, d'-'MMM'-'yy H:m:s 'GMT'", // RFC 850, short year
            "dddd, d'-'MMM'-'yy H:m:s", // RFC 850 no zone
            "ddd, d'-'MMM'-'yyyy H:m:s 'GMT'", // RFC 850, long year
            "ddd MMM d H:m:s yyyy", // ANSI C's asctime() format

            "ddd, d MMM yyyy H:m:s zzz", // RFC 5322
            "ddd, d MMM yyyy H:m:s", // RFC 5322 no zone
            "d MMM yyyy H:m:s zzz", // RFC 5322 no day-of-week
            "d MMM yyyy H:m:s", // RFC 5322 no day-of-week, no zone
        };

        // Valid header token characters are within the range 0x20 < c < 0x7F excluding the following characters
        private const string NonTokenChars = "()<>@,;:\\\"/[]?={}";

        /// <summary>
        /// Quality factor to indicate a perfect match.
        /// </summary>
        public const double Match = 1.0;

        /// <summary>
        /// Quality factor to indicate no match.
        /// </summary>
        public const double NoMatch = 0.0;

        /// <summary>
        /// The default max depth for our formatter is 256
        /// </summary>
        public const int DefaultMaxDepth = 256;

        /// <summary>
        /// The default min depth for our formatter is 1
        /// </summary>
        public const int DefaultMinDepth = 1;

        /// <summary>
        /// HTTP X-Requested-With header field name
        /// </summary>
        public const string HttpRequestedWithHeader = @"x-requested-with";

        /// <summary>
        /// HTTP X-Requested-With header field value
        /// </summary>
        public const string HttpRequestedWithHeaderValue = @"XMLHttpRequest";

        /// <summary>
        /// HTTP Host header field name
        /// </summary>
        public const string HttpHostHeader = "Host";

        /// <summary>
        /// HTTP Version token
        /// </summary>
        public const string HttpVersionToken = "HTTP";

#if !NETFX_CORE // XsdDataContractExporter is not supported in portable libraries
        /// <summary>
        /// An instance of <see cref="XsdDataContractExporter"/>.
        /// </summary>
        public static readonly XsdDataContractExporter XsdDataContractExporter = new XsdDataContractExporter();
#endif

        /// <summary>
        /// Create a default reader quotas with a default depth quota of 1K
        /// </summary>
        /// <returns></returns>
        public static XmlDictionaryReaderQuotas CreateDefaultReaderQuotas()
        {
#if NETFX_CORE // MaxDepth is a DOS mitigation. We don't support MaxDepth in portable libraries because it is strictly client side.
            return XmlDictionaryReaderQuotas.Max;
#else
            return new XmlDictionaryReaderQuotas()
            {
                MaxArrayLength = Int32.MaxValue,
                MaxBytesPerRead = Int32.MaxValue,
                MaxDepth = DefaultMaxDepth,
                MaxNameTableCharCount = Int32.MaxValue,
                MaxStringContentLength = Int32.MaxValue
            };
#endif
        }

        /// <summary>
        /// Remove bounding quotes on a token if present
        /// </summary>
        /// <param name="token">Token to unquote.</param>
        /// <returns>Unquoted token.</returns>
        public static string UnquoteToken(string token)
        {
            if (String.IsNullOrWhiteSpace(token))
            {
                return token;
            }

            if (token.StartsWith("\"", StringComparison.Ordinal) && token.EndsWith("\"", StringComparison.Ordinal) && token.Length > 1)
            {
                return token.Substring(1, token.Length - 2);
            }

            return token;
        }

        public static bool ValidateHeaderToken(string token)
        {
            if (token == null)
            {
                return false;
            }

            foreach (char c in token)
            {
                if (c < 0x21 || c > 0x7E || NonTokenChars.IndexOf(c) != -1)
                {
                    return false;
                }
            }

            return true;
        }

        public static string DateToString(DateTimeOffset dateTime)
        {
            // Format according to RFC1123; 'r' uses invariant info (DateTimeFormatInfo.InvariantInfo)
            return dateTime.ToUniversalTime().ToString("r", CultureInfo.InvariantCulture);
        }

        public static bool TryParseDate(string input, out DateTimeOffset result)
        {
            return DateTimeOffset.TryParseExact(input, dateFormats, DateTimeFormatInfo.InvariantInfo,
                                                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal,
                                                out result);
        }

        /// <summary>
        /// Parses valid integer strings with no leading signs, whitespace or other <see cref="NumberStyles"/>
        /// </summary>
        /// <param name="value">The value to parse</param>
        /// <param name="result">The result</param>
        /// <returns>True if value was valid; false otherwise.</returns>
        public static bool TryParseInt32(string value, out int result)
        {
            return Int32.TryParse(value, NumberStyles.None, NumberFormatInfo.InvariantInfo, out result);
        }
    }
}
