namespace Crypto.IO.TLS.Messages
{
    public class ServerHelloDoneMessage : HandshakeMessage
    {
        public ServerHelloDoneMessage() : base(HandshakeType.ServerHelloDone)
        {
        }

        protected override void Write(EndianBinaryWriter writer)
        {
        }
    }
}