namespace Crypto.IO.TLS.Messages
{
    public class ChangeCipherSpecMessage : Message
    {
        public ChangeCipherSpecMessage(ChangeCipherSpecType type)
        {
            Type = type;
        }

        public ChangeCipherSpecType Type { get; }
    }
}
