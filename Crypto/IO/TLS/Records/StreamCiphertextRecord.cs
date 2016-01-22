using System;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class StreamCiphertextRecord : CiphertextRecord
    {
        public StreamCiphertextRecord(RecordType type, TlsVersion version, ushort length, byte[] content, byte[] mac)
            : base(type, version, length)
        {
            SecurityAssert.NotNull(content);
            SecurityAssert.SAssert(content.Length == length);
            Content = content;

            SecurityAssert.NotNull(mac);
            SecurityAssert.SAssert(mac.Length > 0);
            MAC = mac;
        }

        public byte[] Content { get; }
        public byte[] MAC { get; }

        internal override byte[] GetContents(TlsState state)
        {
            throw new NotImplementedException();
        }
    }
}