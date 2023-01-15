// <copyright file="BitBucketSourceLinkUrlParser.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2017 Datadog, Inc.
// </copyright>

#nullable enable
using System;
using System.Linq;

namespace Datadog.Trace.Pdb.SourceLink
{
    internal class BitBucketSourceLinkUrlParser : SourceLinkUrlParser
    {
        /// <summary>
        /// Extract the git commit sha and repository url from a BitBucket SourceLink mapping string.
        /// For example, for the following SourceLink mapping string:
        ///     https://api.bitbucket.org/2.0/repositories/my-org/my-repo/src/dd35903c688a74b62d1c6a9e4f41371c65704db8/*
        /// It will return:
        ///     - commit sha: dd35903c688a74b62d1c6a9e4f41371c65704db8
        ///     - repository URL: https://bitbucket.org/test-org/test-repo
        /// </summary>
        internal override bool ParseSourceLinkUrl(Uri uri, out string? commitSha, out string? repositoryUrl)
        {
            var segments = uri.AbsolutePath.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (!uri.OriginalString.StartsWith(@"https://api.bitbucket.org/2.0/repositories/") || !IsValidCommitSha(segments[5]))
            {
                repositoryUrl = null;
                commitSha = null;
                return false;
            }

            repositoryUrl = $"https://bitbucket.org/{segments[2]}/{segments[3]}";
            commitSha = segments[5];
            return true;
        }
    }
}