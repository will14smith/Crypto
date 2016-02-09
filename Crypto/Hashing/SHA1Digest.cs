using System;
using System.Collections.Generic;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Hashing
{
    public class SHA1Digest : IDigest
    {
        public ASN1ObjectIdentifier Id => new ASN1ObjectIdentifier("1.3.14.3.2.26");

        public const int ChunkSize = 64;
        public const int OutputSize = 20;

        private uint h0;
        private uint h1;
        private uint h2;
        private uint h3;
        private uint h4;

        private long ml;

        private int workBufferSize;
        private readonly byte[] workBuffer = new byte[ChunkSize];

        private bool complete;

        public SHA1Digest()
        {
            Reset();
        }

        public void Reset()
        {
            h0 = 0x67452301;
            h1 = 0xEFCDAB89;
            h2 = 0x98BADCFE;
            h3 = 0x10325476;
            h4 = 0xC3D2E1F0;

            ml = 0;

            workBufferSize = 0;
            Array.Clear(workBuffer, 0, workBuffer.Length);

            complete = false;
        }

        public void Update(byte[] buffer, int offset, int length)
        {
            SecurityAssert.SAssert(!complete);

            SecurityAssert.NotNull(buffer);
            SecurityAssert.SAssert(offset >= 0 && length >= 0);
            SecurityAssert.SAssert(offset + length <= buffer.Length);

            while (length > 0)
            {
                SecurityAssert.SAssert(workBufferSize < ChunkSize);

                var lengthToTake = Math.Min(length, 64 - workBufferSize);

                Array.Copy(buffer, offset, workBuffer, workBufferSize, lengthToTake);

                length -= lengthToTake;
                offset += lengthToTake;
                workBufferSize += lengthToTake;

                ml += lengthToTake * 8;

                SecurityAssert.SAssert(workBufferSize <= ChunkSize);

                if (workBufferSize == ChunkSize)
                {
                    UpdateChunk();
                }
            }
        }

        private void UpdateChunk()
        {
            SecurityAssert.SAssert(workBufferSize == ChunkSize);

            var w = new uint[80];
            for (var i = 0; i < 16; i++)
            {
                w[i] = EndianBitConverter.Big.ToUInt32(workBuffer, i << 2);
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

            workBufferSize = 0;
            Array.Clear(workBuffer, 0, workBuffer.Length);
        }

        private uint LeftRotate(uint value, int amount)
        {
            SecurityAssert.SAssert(0 <= amount && amount < 32);

            var a = value << amount;
            var b = value >> (32 - amount);

            return a | b;
        }

        public byte[] Digest()
        {
            var paddingLength = 64 - ml / 8 % ChunkSize;
            if (paddingLength <= 8) paddingLength += 64;

            var padding = new byte[paddingLength];
            // first bit is 1
            padding[0] = 0x80;

            Array.Copy(EndianBitConverter.Big.GetBytes((uint)(ml >> 32)), 0, padding, paddingLength - 8, 4);
            Array.Copy(EndianBitConverter.Big.GetBytes((uint)ml), 0, padding, paddingLength - 4, 4);

            Update(padding, 0, padding.Length);
            SecurityAssert.SAssert(workBufferSize == 0);

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
