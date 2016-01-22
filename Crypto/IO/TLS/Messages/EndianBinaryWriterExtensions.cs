using Crypto.Utils;

namespace Crypto.IO.TLS.Messages
{
    internal static class EndianBinaryWriterExtensions
    {
        public static void Write(this EndianBinaryWriter writer, HandshakeType value)
        {
            writer.Write((byte)value);
        }
        public static void Write(this EndianBinaryWriter writer, CipherSuite value)
        {
            writer.Write((ushort)value);
        }
        public static void Write(this EndianBinaryWriter writer, CompressionMethod value)
        {
            writer.Write((byte)value);
        }

        public static void WriteUInt24(this EndianBinaryWriter writer, uint value)
        {
            SecurityAssert.SAssert(value <= 0xFFFFFF);

            var buffer = writer.BitConverter.GetBytes(value);
            writer.Write(buffer, 1, 3);
        }

        public static void WriteVariable(this EndianBinaryWriter writer, byte lengthSize, byte[] value)
        {
            SecurityAssert.SAssert(lengthSize == 1 || lengthSize == 2);

            if (lengthSize == 1)
            {
                SecurityAssert.SAssert(value.Length <= 0xff);
                writer.Write((byte) value.Length);
            }
            else
            {
                SecurityAssert.SAssert(value.Length <= 0xffff);
                writer.Write((ushort)value.Length);
            }

            writer.Write(value);
        }
    }
}