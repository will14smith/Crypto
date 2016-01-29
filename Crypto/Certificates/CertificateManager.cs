using System.Collections.Generic;
using Crypto.Certificates.Keys;

namespace Crypto.Certificates
{
    public class CertificateManager
    {
        // TODO this is really insecure...

        private readonly Dictionary<string, X509Certificate> certificates;
        private readonly Dictionary<PublicKey, PrivateKey> keys;
        private X509Certificate defaultCertificate;

        public CertificateManager()
        {
            certificates = new Dictionary<string, X509Certificate>();
            keys = new Dictionary<PublicKey, PrivateKey>();
        }

        public void AddCertificate(byte[] rawDerBytes)
        {
            var reader = new X509Reader(rawDerBytes);
            var cert = reader.ReadCertificate();

            // TODO get SANs

            var identifier = NormalizeIdentifier(cert.Subject.CommonName);

            if (certificates.Count == 0)
            {
                defaultCertificate = cert;
            }

            certificates.Add(identifier, cert);
        }
        public void AddPrivateKey(byte[] rawDerBytes)
        {
            var reader = new PrivateKeyReader(rawDerBytes);
            var key = reader.ReadKey();

            keys.Add(key.PublicKey, key);
        }

        internal X509Certificate GetDefaultCertificate()
        {
            return defaultCertificate;
        }
        internal X509Certificate GetCertificate(string identifier)
        {
            X509Certificate certificate;
            if (!certificates.TryGetValue(NormalizeIdentifier(identifier), out certificate))
            {
                throw new KeyNotFoundException();
            }

            return certificate;
        }
        internal PrivateKey GetPrivateKey(PublicKey publicKey)
        {
            PrivateKey privateKey;
            if (!keys.TryGetValue(publicKey, out privateKey))
            {
                throw new KeyNotFoundException();
            }

            return privateKey;
        }

        private string NormalizeIdentifier(string identifier)
        {
            //TODO - normalise fully using domain name rules
            return identifier.ToLower();
        }
    }
}
