using System;
using System.IO;
using Crypto.Encryption;
using Crypto.Hashing;
using Crypto.Utils;

namespace Crypto.IO.Signing
{
    public class SignedStream : Stream
    {
        private readonly Stream inner;
        private readonly ICipher signAlgo;
        private readonly IDigest hashAlgo;

        public SignedStream(Stream inner, ICipher signAlgo, IDigest hashAlgo)
        {
            SecurityAssert.NotNull(inner);
            SecurityAssert.SAssert(inner.CanWrite);


            SecurityAssert.NotNull(signAlgo);
            SecurityAssert.NotNull(hashAlgo);

            this.inner = inner;
            this.signAlgo = signAlgo;
            this.hashAlgo = hashAlgo;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            inner.Write(buffer, offset, count);
            hashAlgo.Update(buffer, offset, count);
        }

        public byte[] Sign()
        {
            var hash = hashAlgo.Digest();
            
            throw new NotImplementedException();
        }

        //TODO probably should be an extension method
        public void WriteTlsSignature()
        {
            // enum{ none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6), (255) } HashAlgorithm;
            // enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SignatureAlgorithm;

            // struct { HashAlgorithm hash; SignatureAlgorithm signature; } SignatureAndHashAlgorithm;

            // struct {
            //   SignatureAndHashAlgorithm algorithm;
            //   int16 signature.length
            //   byte[] signature<0..2^16-1>;
            // } DigitallySigned;

            byte hashAlgo = 0;
            byte sigAlgo = 0;

            inner.Write(new[] { hashAlgo, sigAlgo }, 0, 2);

            var signature = Sign();

            inner.Write(EndianBitConverter.Big.GetBytes((ushort)signature.Length), 0, 2);
            inner.Write(signature, 0, signature.Length);
        }

        public override void Flush()
        {
            inner.Flush();
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position
        {
            get { return inner.Position; }
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
