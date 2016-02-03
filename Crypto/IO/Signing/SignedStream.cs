using System;
using System.IO;
using Crypto.Encryption;
using Crypto.Utils;

namespace Crypto.IO.Signing
{
    public class SignedStream : Stream
    {
        private readonly Stream inner;
        private readonly ICipher cipher;

        public SignedStream(Stream inner, ICipher cipher)
        {
            SecurityAssert.NotNull(inner);
            SecurityAssert.NotNull(cipher);
            SecurityAssert.SAssert(inner.CanWrite);

            this.inner = inner;
            this.cipher = cipher;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            inner.Write(buffer, offset, count);
            // TODO update cipher
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return inner.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            inner.SetLength(value);
        }

        public override void Flush()
        {
            inner.Flush();
        }

        public override bool CanRead => false;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position
        {
            get { return inner.Position; }
            set { inner.Position = value; }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}
