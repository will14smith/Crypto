using System;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Hashing
{
    public class HMAC : IDigest
    {
        private enum HMACState
        {
            Uninitialised = 0,
            ProcessedKey,
            InnerHashing,
            HashingDone,
        }

        private readonly IDigest digest;
        private readonly byte[] key;

        private HMACState state = HMACState.Uninitialised;

        public HMAC(IDigest digest, byte[] key)
        {
            SecurityAssert.NotNull(digest);
            SecurityAssert.NotNull(key);

            this.digest = digest;
            this.key = ProcessInputKey(key);

            state = HMACState.ProcessedKey;

            Reset();
        }

        public ASN1ObjectIdentifier Id => null;
        public int BlockSize => digest.BlockSize;
        public int HashSize => digest.HashSize;

        public void Update(byte[] buffer, int offset, int length)
        {
            SecurityAssert.SAssert(state == HMACState.InnerHashing);

            digest.Update(buffer, offset, length);
        }

        public byte[] Digest()
        {
            SecurityAssert.SAssert(state == HMACState.InnerHashing);

            state = HMACState.HashingDone;

            var innerHash = digest.Digest();

            var oPadKey = XorKey(key, 0x5c);
            digest.Reset();
            digest.Update(oPadKey, 0, oPadKey.Length);
            digest.Update(innerHash, 0, innerHash.Length);

            return digest.Digest();
        }

        public void Reset()
        {
            SecurityAssert.SAssert(state != HMACState.Uninitialised);

            var iPadKey = XorKey(key, 0x36);

            digest.Reset();
            digest.Update(iPadKey, 0, iPadKey.Length);

            state = HMACState.InnerHashing;
        }

        private byte[] ProcessInputKey(byte[] bytes)
        {
            var blockLength = digest.BlockSize / 8;
            var key = new byte[blockLength];

            if (bytes.Length > blockLength)
            {
                state = HMACState.Uninitialised;

                digest.Reset();
                digest.Update(bytes, 0, bytes.Length);
                key = digest.Digest();
            }
            else
            {
                Array.Copy(bytes, key, bytes.Length);
            }

            return key;
        }
        private byte[] XorKey(byte[] bytes, byte param)
        {
            var result = new byte[bytes.Length];

            for (var i = 0; i < bytes.Length; i++)
            {
                result[i] = (byte)(bytes[i] ^ param);
            }

            return result;
        }

    }
}
