using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Crypto.Certificates.Keys;

namespace Crypto.Certificates
{
    public class X509Certificate
    {
        public byte Version { get; }
        public BigInteger SerialNumber { get; }

        public X509Validity Validity { get; }

        public X509AlgorithmIdentifier SignatureAlgorithm { get; }
        public BitArray Signature { get; }

        public X509Name Issuer { get; }
        public X509Name Subject { get; }

        public X509AlgorithmIdentifier SubjectPublicKeyAlgorithm { get; }
        public PublicKey SubjectPublicKey { get; }

        public IReadOnlyList<X509Extension> Extensions { get; }

        public X509Certificate(byte version, BigInteger serialNumber, X509Validity validity,
            X509Name issuer, X509Name subject, X509AlgorithmIdentifier subjectPublicKeyAlgorithm, PublicKey subjectPublicKey,
            X509AlgorithmIdentifier signatureAlgorithm, BitArray signature, IEnumerable<X509Extension> extensions)
        {
            Version = version;
            SerialNumber = serialNumber;
            Validity = validity;

            SignatureAlgorithm = signatureAlgorithm;
            Signature = signature;

            Issuer = issuer;
            Subject = subject;

            SubjectPublicKeyAlgorithm = subjectPublicKeyAlgorithm;
            SubjectPublicKey = subjectPublicKey;

            Extensions = extensions.ToList();
        }
    }
}
