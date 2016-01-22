using System.IO;
using Crypto.Utils;

namespace Crypto.IO.TLS.Messages
{
    public abstract class HandshakeMessage : Message
    {
        protected HandshakeMessage(HandshakeType type)
        {
            Type = type;
        }

        public HandshakeType Type { get; }
        
        public byte[] GetBytes()
        {
            using (var ms = new MemoryStream())
            {
                var writer = new EndianBinaryWriter(EndianBitConverter.Big, ms);

                writer.Write(Type);
                writer.WriteUInt24(0);

                Write(writer);

                writer.Seek(1, SeekOrigin.Begin);
                writer.WriteUInt24((uint)ms.Length - 4);

                return ms.GetBuffer();
            }
        }

        protected abstract void Write(EndianBinaryWriter writer);
    }
}
