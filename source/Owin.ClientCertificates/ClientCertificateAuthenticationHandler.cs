/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using log4net;

namespace Thinktecture.IdentityModel.Owin
{
    public class ClientCertificateAuthenticationHandler : AuthenticationHandler<ClientCertificateAuthenticationOptions>
    {
        private static ILog log = LogManager.GetLogger(typeof(ClientCertificateAuthenticationHandler));
        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            log.Info("ClientCertificateAuthenticationHandler is called");
            var cert = Context.Get<X509Certificate2>("ssl.ClientCertificate");

            if (cert == null)
            {
                return Task.FromResult<AuthenticationTicket>(null);
            }
            log.Info($"ssl.ClientCertificate {cert.FriendlyName} {cert.SubjectName}");
            try
            {
                Options.Validator.Validate(cert);
            }
            catch (SecurityTokenValidationException)
            {
                return Task.FromResult<AuthenticationTicket>(null);
            }
            log.Info("ClientCertificate is valid");
            var identity = Identity.CreateFromCertificate(
                cert,
                Options.AuthenticationType,
                Options.CreateExtendedClaimSet);

            var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
            return Task.FromResult<AuthenticationTicket>(ticket);
        }
    }
}