// <copyright file="OpenLdapCrash.cs" company="Datadog">
// Unless explicitly stated otherwise all files in this repository are licensed under the Apache 2 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.
// </copyright>

#if NET5_0_OR_GREATER
using System;
using System.DirectoryServices.Protocols;
using System.Net;

namespace Samples.Computer01
{
    internal class OpenLdapCrash : ScenarioBase
    {
        public override void OnProcess()
        {
            ConnectToLdapServer();
        }

        private void ConnectToLdapServer()
        {
            try
            {
                using (var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier("localhost", 389), new NetworkCredential("cn=admin,dc=dd-trace-dotnet,dc=com", "Passw0rd"), AuthType.Basic))
                {
                    ldapConnection.SessionOptions.ProtocolVersion = 3;
                    ldapConnection.Bind();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[Error] An error occured while trying to connect to the LDAP server: " + e.Message);
            }
        }
    }
}
#endif
