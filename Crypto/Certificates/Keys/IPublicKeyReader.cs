using System.Collections;

namespace Crypto.Certificates.Keys
{
    public interface IPublicKeyReader
    {
        PublicKey Read(X509AlgorithmIdentifier algorithm, BitArray bits);
    }
}
