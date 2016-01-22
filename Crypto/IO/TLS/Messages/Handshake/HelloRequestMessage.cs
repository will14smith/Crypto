namespace Crypto.IO.TLS.Messages
{
    public class HelloRequestMessage : HandshakeMessage
    {
        public HelloRequestMessage() : base(HandshakeType.HelloRequest, 0)
        {
        }
    }
}
