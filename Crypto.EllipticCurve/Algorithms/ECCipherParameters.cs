using Crypto.EllipticCurve.Maths;
using Crypto.Encryption.Parameters;

namespace Crypto.EllipticCurve.Algorithms
{
    public class ECCipherParameters : ICipherParameters
    {
        public PrimeDomainParameters Domain { get; }
        public ECPublicKey PublicKey { get; }
        public ECPrivateKey PrivateKey { get; }
        
        public ECCipherParameters(PrimeDomainParameters domain, ECPublicKey publicKey)
        {
            Domain = domain;
            PublicKey = publicKey;
        }

        public ECCipherParameters(PrimeDomainParameters domain, ECPrivateKey privateKey)
        {
            Domain = domain;
            PublicKey = (ECPublicKey)privateKey.PublicKey;
            PrivateKey = privateKey;
        }
    }
}
