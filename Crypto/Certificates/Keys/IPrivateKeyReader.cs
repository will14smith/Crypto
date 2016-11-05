using Crypto.Utils;

namespace Crypto.Certificates.Keys
{
    public interface IPrivateKeyReader
    {
        Option<PrivateKey> TryRead(byte[] input);
    }
}