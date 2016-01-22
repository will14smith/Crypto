using System;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public class CompressedRecord : Record
    {
        public CompressedRecord(RecordType type, TlsVersion version, ushort length)
            : this(type, version, length, new byte[length])
        {
        }
        public CompressedRecord(RecordType type, TlsVersion version, ushort length, byte[] fragment)
            : base(type, version, length)
        {
            // RFC5246 6.2.2: Compression must be lossless and may not increase the content length by more than 1024 bytes
            SecurityAssert.SAssert(length <= 0x4400);

            SecurityAssert.NotNull(fragment);
            SecurityAssert.SAssert(fragment.Length == length);
            Fragment = fragment;
        }

        public byte[] Fragment { get; }

        internal override byte[] GetContents(TlsState state)
        {
            throw new NotImplementedException();
        }
    }
}