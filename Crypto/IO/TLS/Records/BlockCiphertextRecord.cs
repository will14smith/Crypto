using System;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class BlockCiphertextRecord : CiphertextRecord
    {
        public BlockCiphertextRecord(RecordType type, TlsVersion version, ushort length, byte[] content, byte[] mac, byte[] padding, byte paddingLength)
            : base(type, version, length)
        {
            SecurityAssert.NotNull(content);
            SecurityAssert.SAssert(content.Length == length);
            Content = content;

            SecurityAssert.NotNull(mac);
            SecurityAssert.SAssert(mac.Length > 0);
            MAC = mac;
            Padding = padding;

            SecurityAssert.NotNull(padding);
            SecurityAssert.SAssert(padding.Length == paddingLength);
            PaddingLength = paddingLength;
        }

        public byte[] Content { get; }
        public byte[] MAC { get; }
        public byte[] Padding { get; set; }
        public byte PaddingLength { get; set; }

        internal override byte[] GetContents(TlsState state)
        {
            throw new NotImplementedException();
        }
    }
}