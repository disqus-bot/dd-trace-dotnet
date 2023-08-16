// <copyright file="TracerSettingsConstants.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

namespace Datadog.Trace.Configuration;

internal class TracerSettingsConstants
{
    /// <summary>
    /// Default obfuscation query string regex if none specified via env DD_OBFUSCATION_QUERY_STRING_REGEXP
    /// Warning: this regex crashes the native .net regex engine under netcoreapp2.1 and linux and arm64, dont use on manual instrum.
    /// </summary>
    internal const string DefaultObfuscationQueryStringRegex = """
                                                                (?ix)
                                                               (?: # JSON-ish leading quote
                                                               (?:"|%22)?
                                                               )
                                                               (?: # common keys
                                                               (?:old[-_]?|new[-_]?)?p(?:ass)?w(?:or)?d(?:1|2)? # pw, password variants
                                                               |pass(?:[-_]?phrase)?  # pass, passphrase variants
                                                               |secret
                                                               |(?: # key, key_id variants
                                                               api[-_]?
                                                               |private[-_]?
                                                               |public[-_]?
                                                               |access[-_]?
                                                               |secret[-_]?
                                                               )key(?:[-_]?id)?
                                                               |token
                                                               |consumer[-_]?(?:id|key|secret)
                                                               |sign(?:ed|ature)?
                                                               |auth(?:entication|orization)?
                                                               )
                                                               (?:
                                                               # '=' query string separator, plus value til next '&' separator
                                                               (?:\s|%20)*(?:=|%3D)[^&]+
                                                               # JSON-ish '": "somevalue"', key being handled with case above, without the opening '"'
                                                               |(?:"|%22)                                     # closing '"' at end of key
                                                               (?:\s|%20)*(?::|%3A)(?:\s|%20)*               # ':' key-value spearator, with surrounding spaces
                                                               (?:"|%22)                                     # opening '"' at start of value
                                                               (?:%2[^2]|%[^2]|[^"%])+                       # value
                                                               (?:"|%22)                                     # closing '"' at end of value
                                                               )
                                                               |(?: # other common secret values
                                                               bearer(?:\s|%20)+[a-z0-9._\-]+
                                                               |token(?::|%3A)[a-z0-9]{13}
                                                               |gh[opsu]_[0-9a-zA-Z]{36}
                                                               |ey[I-L](?:[\w=-]|%3D)+\.ey[I-L](?:[\w=-]|%3D)+(?:\.(?:[\w.+/=-]|%3D|%2F|%2B)+)?
                                                               |-{5}BEGIN(?:[a-z\s]|%20)+PRIVATE(?:\s|%20)KEY-{5}[^\-]+-{5}END(?:[a-z\s]|%20)+PRIVATE(?:\s|%20)KEY(?:-{5})?(?:\n|%0A)?
                                                               |(?:ssh-(?:rsa|dss)|ecdsa-[a-z0-9]+-[a-z0-9]+)(?:\s|%20|%09)+(?:[a-z0-9/.+]|%2F|%5C|%2B){100,}(?:=|%3D)*(?:(?:\s|%20|%09)+[a-z0-9._-]+)?
                                                               )
                                                               """;
}
