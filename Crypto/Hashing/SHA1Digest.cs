using System;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Hashing
{
    public class SHA1Digest : BlockDigest
    {
        public override ASN1ObjectIdentifier Id => new ASN1ObjectIdentifier("1.3.14.3.2.26");
        public override int BlockSize => 512;
        public override int HashSize => 160;

        private uint h0;
        private uint h1;
        private uint h2;
        private uint h3;
        private uint h4;

        private bool complete;

        public SHA1Digest()
        {
            Reset();
        }

        private SHA1Digest(SHA1Digest source)
            : base(source)
        {
            h0 = source.h0;
            h1 = source.h1;
            h2 = source.h2;
            h3 = source.h3;
            h4 = source.h4;

            complete = source.complete;
        }

        public override void Reset()
        {
            base.Reset();

            h0 = 0x67452301;
            h1 = 0xEFCDAB89;
            h2 = 0x98BADCFE;
            h3 = 0x10325476;
            h4 = 0xC3D2E1F0;

            complete = false;
        }

        public override IDigest Clone()
        {
            return new SHA1Digest(this);
        }

        public override void Update(byte[] buffer, int offset, int length)
        {
            SecurityAssert.SAssert(!complete);

            base.Update(buffer, offset, length);
        }

        protected override void UpdateBlock(byte[] buffer)
        {
            SecurityAssert.SAssert(!complete);

            var w = new uint[80];
            for (var i = 0; i < 16; i++)
            {
                w[i] = EndianBitConverter.Big.ToUInt32(buffer, i << 2);
            }
            for (var i = 16; i < 80; i++) { w[i] = LeftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1); }

            var a = h0;
            var b = h1;
            var c = h2;
            var d = h3;
            var e = h4;

            for (var i = 0; i < 80; i++)
            {
                uint f, k;
                if (i < 20)
                {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999;
                }
                else if (i < 40)
                {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if (i < 60)
                {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else
                {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                var temp = LeftRotate(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = LeftRotate(b, 30);
                b = a;
                a = temp;
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }

        private uint LeftRotate(uint value, int amount)
        {
            SecurityAssert.SAssert(0 <= amount && amount < 32);

            var a = value << amount;
            var b = value >> (32 - amount);

            return a | b;
        }

        public override byte[] Digest()
        {
            var paddingLength = 64 - (MessageSize % BlockSize) / 8;
            if (paddingLength <= 8) paddingLength += 64;

            var padding = new byte[paddingLength];
            // first bit is 1
            padding[0] = 0x80;

            Array.Copy(EndianBitConverter.Big.GetBytes(MessageSize), 0, padding, paddingLength - 8, 8);

            Update(padding, 0, padding.Length);
            SecurityAssert.SAssert(WorkBufferEmpty);

            complete = true;

            var digest = new byte[20];

            Array.Copy(EndianBitConverter.Big.GetBytes(h0), 0, digest, 0, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes(h1), 0, digest, 4, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes(h2), 0, digest, 8, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes(h3), 0, digest, 12, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes(h4), 0, digest, 16, 4);

            return digest;
        }
    }
}
