using Crypto.IO.TLS.Messages.Handshake;

namespace Crypto.IO.TLS.Extensions
{
    public interface ITlsExtension
    {
        HelloExtension GenerateHello();
    }
}