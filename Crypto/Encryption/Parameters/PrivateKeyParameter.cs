using Crypto.Certificates.Keys;

namespace Crypto.Encryption.Parameters
{
    public class PrivateKeyParameter : ICipherParameters
    {
        public PrivateKeyParameter(PrivateKey key)
        {
            Key = key;
        }

        public PrivateKey Key { get; }
    }
}