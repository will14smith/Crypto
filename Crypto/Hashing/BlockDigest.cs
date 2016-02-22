using System;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Hashing
{
    /// <summary>
    /// Sizes are in bits, Lengths in bytes
    /// </summary>
    public abstract class BlockDigest : IDigest
    {
        public abstract ASN1ObjectIdentifier Id { get; }
        public abstract int BlockSize { get; }
        public abstract int HashSize { get; }

        protected long MessageSize { get; private set; }

        private int workBufferLength;
        private readonly byte[] workBuffer;

        protected bool WorkBufferEmpty => workBufferLength == 0;

        protected BlockDigest()
        {
            workBuffer = new byte[BlockSize / 8];
        }

        protected BlockDigest(BlockDigest source) : this()
        {
            MessageSize = source.MessageSize;

            workBufferLength = source.workBufferLength;
            Array.Copy(source.workBuffer, workBuffer, workBufferLength);
        }

        public virtual void Update(byte[] buffer, int offset, int length)
        {
            SecurityAssert.NotNull(buffer);
            SecurityAssert.SAssert(offset >= 0 && length >= 0);
            SecurityAssert.SAssert(offset + length <= buffer.Length);

            while (length > 0)
            {
                SecurityAssert.SAssert(workBufferLength < BlockSize / 8);

                var lengthToTake = Math.Min(length, workBuffer.Length - workBufferLength);

                Array.Copy(buffer, offset, workBuffer, workBufferLength, lengthToTake);

                length -= lengthToTake;
                offset += lengthToTake;
                workBufferLength += lengthToTake;

                MessageSize += lengthToTake * 8;

                SecurityAssert.SAssert(workBufferLength <= BlockSize / 8);

                if (workBufferLength == BlockSize / 8)
                {
                    UpdateBlock(workBuffer);

                    workBufferLength = 0;
                    Array.Clear(workBuffer, 0, workBuffer.Length);
                }
            }
        }

        public abstract byte[] Digest();
        public virtual void Reset()
        {
            MessageSize = 0;

            workBufferLength = 0;
            Array.Clear(workBuffer, 0, workBuffer.Length);
        }

        public abstract IDigest Clone();

        protected abstract void UpdateBlock(byte[] buffer);
    }
}
