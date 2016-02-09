using System;
using System.IO;
using Crypto.Encryption;
using Crypto.Hashing;
using Crypto.Utils;

namespace Crypto.IO.Signing
{
    public class SignedStream : Stream
    {
        public Stream InnerStream { get; }
        public ISignatureCipher SignatureAlgorithm { get; }
        public IDigest HashAlgorithm { get; }

        public SignedStream(Stream inner, ISignatureCipher signAlgo, IDigest hashAlgo)
        {
            SecurityAssert.NotNull(inner);
            SecurityAssert.SAssert(inner.CanWrite);
            
            SecurityAssert.NotNull(signAlgo);
            SecurityAssert.NotNull(hashAlgo);

            InnerStream = inner;
            SignatureAlgorithm = signAlgo;
            HashAlgorithm = hashAlgo;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            InnerStream.Write(buffer, offset, count);
            HashAlgorithm.Update(buffer, offset, count);
        }

        public byte[] Sign()
        {
            // not input because Write updates the HashAlgo
            return SignatureAlgorithm.Sign(new byte[0], HashAlgorithm);
        }

        public override void Flush()
        {
            InnerStream.Flush();
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => InnerStream.Length;
        public override long Position
        {
            get { return InnerStream.Position; }
            set { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }
    }
}

