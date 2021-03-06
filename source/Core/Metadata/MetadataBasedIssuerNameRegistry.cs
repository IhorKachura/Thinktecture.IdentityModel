﻿/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see LICENSE
 */

using System;
using System.Configuration;
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Threading.Tasks;
using System.Xml;

namespace Thinktecture.IdentityModel.Metadata
{
    public class MetadataBasedIssuerNameRegistry : IssuerNameRegistry
    {
        private Uri metadataAddress;
        private string issuerName;
        X509CertificateValidationMode mode;

        private static volatile ConfigurationBasedIssuerNameRegistry _registry;
        private static object _registryLock = new object();

        public MetadataBasedIssuerNameRegistry()
        {
        }

        public MetadataBasedIssuerNameRegistry(
            Uri metadataAddress,
            string issuerName,
            X509CertificateValidationMode mode = X509CertificateValidationMode.None,
            bool lazyLoad = false)
        {
            if (metadataAddress == null) throw new ArgumentNullException("metadataAddress");
            if (String.IsNullOrWhiteSpace(issuerName)) throw new ArgumentNullException("issuerName");

            this.metadataAddress = metadataAddress;
            this.issuerName = issuerName;
            this.mode = mode;

            if (!lazyLoad)
            {
                LoadMetadata();
            }
        }

        public override string GetIssuerName(SecurityToken securityToken)
        {
            if (_registry == null)
            {
                lock (_registryLock)
                {
                    if (_registry == null)
                    {
                        LoadMetadata();
                    }
                }
            }

            return _registry.GetIssuerName(securityToken);
        }

        protected virtual Stream GetMetadataStream()
        {
            var client = new HttpClient { BaseAddress = metadataAddress };
            return client.GetStreamAsync("").Result;
        }

        protected async virtual Task<Stream> GetMetadataStreamAsync()
        {
            var client = new HttpClient { BaseAddress = metadataAddress };
            return await client.GetStreamAsync("");
        }

        protected virtual void LoadMetadata()
        {
            using (var stream = GetMetadataStream())
            {
                var serializer = new MetadataSerializer();
                serializer.CertificateValidationMode = mode;

                var md = serializer.ReadMetadata(stream);
                var ed = md as EntityDescriptor;
                var stsd = (SecurityTokenServiceDescriptor)ed.RoleDescriptors.FirstOrDefault(x => x is SecurityTokenServiceDescriptor);

                var registry = new ConfigurationBasedIssuerNameRegistry();
                foreach (var key in stsd.Keys)
                {
                    var clause = key.KeyInfo.FirstOrDefault() as X509RawDataKeyIdentifierClause;
                    if (clause != null)
                    {
                        var cert = new X509Certificate2(clause.GetX509RawData());
                        registry.AddTrustedIssuer(cert.Thumbprint, issuerName);
                    }
                }

                _registry = registry;
            }
        }

        public override void LoadCustomConfiguration(XmlNodeList nodeList)
        {
            if (nodeList == null || nodeList.Count == 0)
            {
                throw new ConfigurationErrorsException("No configuration provided.");
            }

            var node = nodeList.Cast<XmlNode>().FirstOrDefault(x => x.LocalName == "trustedIssuerMetadata");
            if (node == null)
            {
                throw new ConfigurationErrorsException("Expected 'trustedIssuerMetadata' element.");
            }

            var elem = node as XmlElement;

            var name = elem.Attributes["issuerName"];
            if (name == null || String.IsNullOrWhiteSpace(name.Value))
            {
                throw new ConfigurationErrorsException("Expected 'issuerName' attribute.");
            }

            var address = elem.Attributes["metadataAddress"];
            if (address == null || String.IsNullOrWhiteSpace(address.Value))
            {
                throw new ConfigurationErrorsException("Expected 'metadataAddress' attribute.");
            }

            this.metadataAddress = new Uri(address.Value);
            this.issuerName = name.Value;
        }
    }
}
