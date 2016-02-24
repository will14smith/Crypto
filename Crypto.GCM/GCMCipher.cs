using System;
using Crypto.Encryption;
using Crypto.Encryption.AEAD;
using Crypto.Encryption.Modes;
using Crypto.Encryption.Parameters;
using Crypto.Hashing;
using Crypto.Utils;

namespace Crypto.GCM
{
    public class GCMCipher : IAEADBlockCipher
    {
        private long ivSize;
        private long aSize;
        private long cSize;

        private byte[] h;
        private byte[] j0;
        private IDigest tagHash;

        public GCMCipher(IBlockCipher cipher)
        {
            SecurityAssert.SAssert(cipher.BlockLength == 16);
            SecurityAssert.SAssert(cipher.KeyLength >= 16);

            Cipher = cipher;
            buffer = new byte[BlockLength];
        }

        public IBlockCipher Cipher { get; }

        public int BlockLength => Cipher.BlockLength;
        public int KeySize => Cipher.KeyLength;
        public int TagLength => 16;

        public void Init(ICipherParameters parameters)
        {
            // setup AAD
            var aadParam = parameters as AADParameter;
            SecurityAssert.NotNull(aadParam);

            var a = aadParam.AAD;
            aSize = a.Length * 8;

            // setup IV
            var ivParam = aadParam.Parameters as IVParameter;
            SecurityAssert.NotNull(ivParam);

            var iv = ivParam.IV;
            ivSize = iv.Length * 8;

            // setup cipher
            Cipher.Init(ivParam.Parameters);

            // setup H subkey
            h = new byte[16];
            Cipher.EncryptBlock(new byte[16], 0, h, 0);

            // setup tag hash
            tagHash = new GHash(h);
            tagHash.Update(a, 0, a.Length);
            var tagAADPaddingLength = 16 - a.Length % 16;
            tagHash.Update(new byte[tagAADPaddingLength], 0, tagAADPaddingLength);

            // setup pre-counter block
            if (iv.Length == 12)
            {
                // IV || 0^31 ||1

                j0 = new byte[16];
                Array.Copy(iv, j0, 12);
                j0[15] = 1;
            }
            else
            {
                // GHASH_H(IV || 0^(s+64) || [len(IV)])

                var j0PaddingLength = 8 + (16 - iv.Length % 16) % 16;

                var j0Hash = new GHash(h);
                j0Hash.Update(iv, 0, iv.Length);
                j0Hash.Update(new byte[j0PaddingLength], 0, j0PaddingLength);
                j0Hash.Update(EndianBitConverter.Big.GetBytes(ivSize), 0, sizeof(long));

                j0 = j0Hash.Digest();
            }

            ctr = new CTRBlockCipher(Cipher);
            ctr.Init(new IVParameter(null, j0));
            ctr.Inc();

            cSize = 0;
        }

        private readonly byte[] buffer;
        private int bufferOffset;
        private CTRBlockCipher ctr;

        public int Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            var total = 0;

            for (var i = 0; i < length; i++)
            {
                buffer[bufferOffset++] = input[inputOffset + i];

                if (bufferOffset == BlockLength)
                {
                    EncryptBlock(output, outputOffset);
                    outputOffset += BlockLength;
                    total += BlockLength;
                }
            }

            return total;
        }

        private void EncryptBlock(byte[] output, int outputOffset)
        {
            // encrypt block
            var ciphertext = new byte[BlockLength];
            ctr.EncryptBlock(buffer, 0, ciphertext, 0);

            // copy to output
            Array.Copy(ciphertext, 0, output, outputOffset, bufferOffset);

            // update tag hash
            tagHash.Update(output, outputOffset, bufferOffset);
            cSize += bufferOffset * 8;

            // clear buffer
            bufferOffset = 0;
            Array.Clear(buffer, 0, BlockLength);
        }

        public int EncryptFinal(byte[] output, int offset)
        {
            var total = 0;

            if (bufferOffset != 0)
            {
                var len = bufferOffset;

                EncryptBlock(output, offset);

                total += len;
                offset += len;
            }

            var tagCiphertextPaddingLength = (16 - (int)(cSize / 8) % 16) % 16;
            tagHash.Update(new byte[tagCiphertextPaddingLength], 0, tagCiphertextPaddingLength);
            tagHash.Update(EndianBitConverter.Big.GetBytes(aSize), 0, sizeof(long));
            tagHash.Update(EndianBitConverter.Big.GetBytes(cSize), 0, sizeof(long));

            var ctr = new CTRBlockCipher(Cipher);
            ctr.Init(new IVParameter(null, j0));

            ctr.EncryptBlock(tagHash.Digest(), 0, output, offset);
            total += BlockLength;

            return total;
        }

        public int Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
        {
            var total = 0;

            for (var i = 0; i < length; i++)
            {
                buffer[bufferOffset++] = input[inputOffset + i];

                if (bufferOffset == BlockLength)
                {
                    DecryptBlock(output, outputOffset);
                    outputOffset += BlockLength;
                    total += BlockLength;
                }
            }

            return total;
        }

        private void DecryptBlock(byte[] output, int outputOffset)
        {
            // encrypt block
            var plaintext = new byte[BlockLength];
            ctr.DecryptBlock(buffer, 0, plaintext, 0);

            // copy to output
            Array.Copy(plaintext, 0, output, outputOffset, bufferOffset);

            // update tag hash
            tagHash.Update(buffer, 0, bufferOffset);
            cSize += bufferOffset * 8;

            // clear buffer
            bufferOffset = 0;
            Array.Clear(buffer, 0, BlockLength);
        }

        public int DecryptFinal(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            SecurityBufferAssert.AssertBuffer(input, inputOffset, TagLength);
            SecurityBufferAssert.AssertBuffer(output, outputOffset, bufferOffset);

            var total = 0;
            if (bufferOffset != 0)
            {
                total += bufferOffset;
                inputOffset += bufferOffset;

                DecryptBlock(output, outputOffset);
            }

            var tagCiphertextPaddingLength = (16 - (int)(cSize / 8) % 16) % 16;
            tagHash.Update(new byte[tagCiphertextPaddingLength], 0, tagCiphertextPaddingLength);
            tagHash.Update(EndianBitConverter.Big.GetBytes(aSize), 0, sizeof(long));
            tagHash.Update(EndianBitConverter.Big.GetBytes(cSize), 0, sizeof(long));

            var ctr = new CTRBlockCipher(Cipher);
            ctr.Init(new IVParameter(null, j0));

            var calculatedTag = new byte[16];
            ctr.EncryptBlock(tagHash.Digest(), 0, calculatedTag, 0);

            var tag = new byte[16];
            Array.Copy(input, inputOffset, tag, 0, TagLength);

            SecurityAssert.HashAssert(calculatedTag, tag);

            return total;
        }
    }
}
