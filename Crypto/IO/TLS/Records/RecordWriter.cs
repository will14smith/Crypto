using System;
using System.IO;
using Crypto.Encryption;
using Crypto.Encryption.Parameters;
using Crypto.Hashing;
using Crypto.Utils;
using Crypto.Utils.IO;
using StreamWriter = Crypto.Utils.IO.StreamWriter;

namespace Crypto.IO.TLS
{
    /// <summary>
    /// this handles fragmentation
    /// </summary>
    public class RecordWriter : StreamWriter
    {
        private readonly TlsState state;
        private long seqNum;

        public RecordWriter(TlsState state, Stream stream) : base(stream)
        {
            this.state = state;
        }

        public void WriteRecord(Record record)
        {
            //TODO fragmentation
            if (state.WriteProtected)
            {
                Writer.Write(record.Type);
                Writer.Write(record.Version);

                var cipherTextBuffer = GetCipherTextBuffer(record);

                Writer.Write((ushort)(cipherTextBuffer.Length));
                Writer.Write(cipherTextBuffer);
            }
            else
            {
                Writer.Write(GetPlainTextBuffer(record));
            }
        }

        private byte[] GetCipherTextBuffer(Record record)
        {
            var cipher = state.GetCipher();
            if (cipher is BlockCipherAdapter)
            {
                return GetBlockCipherBuffer((BlockCipherAdapter)cipher, record);
            }
            else if (cipher is AEADCipherAdapter)
            {
                return GetAEADCipherBuffer((AEADCipherAdapter)cipher, record);
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        private byte[] GetBlockCipherBuffer(BlockCipherAdapter cipher, Record record)
        {
            var macAlgo = state.GetMAC(false);
            var mac = CreateMAC(macAlgo, seqNum, record);

            var iv = RandomGenerator.RandomBytes(cipher.BlockLength);

            var payloadLength = record.Data.Length + macAlgo.HashSize / 8;

            var padding = (byte)(cipher.BlockLength - 1 - payloadLength % cipher.BlockLength);
            // TODO padding can be upto 255, so possible add more than the minimum

            payloadLength += padding + 1;

            var plaintext = new byte[payloadLength];
            var payload = new byte[iv.Length + payloadLength];
            Array.Copy(iv, payload, iv.Length);

            var offset = 0;

            Array.Copy(record.Data, 0, plaintext, offset, record.Data.Length);
            offset += record.Data.Length;

            Array.Copy(mac, 0, plaintext, offset, mac.Length);
            offset += mac.Length;

            for (; offset < payloadLength; offset++)
            {
                plaintext[offset] = padding;
            }

            cipher.Init(new IVParameter(state.GetBlockCipherParameters(false), iv));
            cipher.Encrypt(plaintext, 0, payload, iv.Length, plaintext.Length);

            seqNum++;

            return payload;
        }

        private byte[] CreateMAC(IDigest macAlgo, long seqNum, Record record)
        {
            macAlgo.Update(EndianBitConverter.Big.GetBytes(seqNum), 0, sizeof(long));
            macAlgo.Update(new[] { (byte)record.Type, record.Version.Major, record.Version.Major }, 0, 3);
            macAlgo.Update(EndianBitConverter.Big.GetBytes((ushort)record.Data.Length), 0, sizeof(ushort));
            macAlgo.Update(record.Data, 0, record.Length);

            return macAlgo.Digest();
        }

        private byte[] GetAEADCipherBuffer(AEADCipherAdapter cipher, Record record)
        {
            // TODO parametrised from CipherSpec
            var explicitNonceLength = 8;
            var nonce = RandomGenerator.RandomBytes(explicitNonceLength);

            var aad = new byte[13];
            Array.Copy(EndianBitConverter.Big.GetBytes(seqNum), 0, aad, 0, 8);
            Array.Copy(new[] { (byte)record.Type, record.Version.Major, record.Version.Major }, 0, aad, 8, 3);
            Array.Copy(EndianBitConverter.Big.GetBytes((ushort)record.Length), 0, aad, 11, 2);

            var payload = new byte[8 + record.Length + cipher.BlockLength];
            Array.Copy(nonce, payload, explicitNonceLength);

            cipher.Init(state.GetAEADParameters(false, aad, nonce));
            cipher.Encrypt(record.Data, 0, payload, explicitNonceLength, record.Data.Length);

            return payload;
        }

        private byte[] GetPlainTextBuffer(Record record)
        {
            using (var ms = new MemoryStream())
            using (var msWriter = new EndianBinaryWriter(EndianBitConverter.Big, ms))
            {
                msWriter.Write(record.Type);
                msWriter.Write(record.Version);
                msWriter.Write((ushort)record.Length);
                msWriter.Write(record.Data, 0, record.Length);

                return ms.ToArray();
            }
        }
    }
}