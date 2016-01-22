using System;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class AEADCiphertextRecord : CiphertextRecord
    {
        public AEADCiphertextRecord(RecordType type, TlsVersion version, ushort length, byte[] nonce, byte[] content)
            : base(type, version, length)
        {
            SecurityAssert.NotNull(nonce);
            SecurityAssert.SAssert(nonce.Length > 0);
            Nonce = nonce;

            SecurityAssert.NotNull(content);
            SecurityAssert.SAssert(content.Length == length);
            Content = content;
        }

        public byte[] Nonce { get; }
        public byte[] Content { get; }

        internal override byte[] GetContents(TlsState state)
        {
            throw new NotImplementedException();
        }
    }
}