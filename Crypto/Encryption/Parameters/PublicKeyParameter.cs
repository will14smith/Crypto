using Crypto.Certificates.Keys;

namespace Crypto.Encryption.Parameters
{
    public class PublicKeyParameter : ICipherParameters
    {
        public PublicKeyParameter(PublicKey key)
        {
            Key = key;
        }

        public PublicKey Key { get; }
    }
}
