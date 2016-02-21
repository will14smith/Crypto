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
                Writer.Write(GetCipherTextBuffer(record));
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
            else
            {
                throw new NotImplementedException();
            }
        }

        private byte[] GetBlockCipherBuffer(BlockCipherAdapter cipher, Record record)
        {
            var macAlgo = state.GetMAC(false);
            var mac = CreateMAC(macAlgo, seqNum, record);

            var payloadLength = record.Data.Length + macAlgo.HashSize / 8;

            var padding = (byte)(cipher.BlockLength - 1 - payloadLength % cipher.BlockLength);
            // TODO padding can be upto 255, so possible add more than the minimum

            payloadLength += padding + 1;

            var payload = new byte[payloadLength];
            var ciphertext = new byte[payloadLength];

            var offset = 0;

            Array.Copy(record.Data, 0, payload, offset, record.Data.Length);
            offset += record.Data.Length;

            Array.Copy(mac, 0, payload, offset, mac.Length);
            offset += mac.Length;

            for (; offset < payloadLength; offset++)
            {
                payload[offset] = padding;
            }

            var iv = RandomGenerator.RandomBytes(cipher.BlockLength);

            cipher.Init(new IVParameter(state.GetBlockCipherParameters(false), iv));
            cipher.Encrypt(payload, 0, ciphertext, 0, payload.Length);

            seqNum++;

            using (var ms = new MemoryStream())
            using (var msWriter = new EndianBinaryWriter(EndianBitConverter.Big, ms))
            {
                msWriter.Write(record.Type);
                msWriter.Write(record.Version);
                msWriter.Write((ushort)(iv.Length + ciphertext.Length));
                msWriter.Write(iv, 0, iv.Length);
                msWriter.Write(ciphertext, 0, ciphertext.Length);

                return ms.ToArray();
            }
        }

        private byte[] CreateMAC(IDigest macAlgo, long seqNum, Record record)
        {
            macAlgo.Update(EndianBitConverter.Big.GetBytes(seqNum), 0, sizeof(long));
            macAlgo.Update(new[] { (byte)record.Type, record.Version.Major, record.Version.Major }, 0, 3);
            macAlgo.Update(EndianBitConverter.Big.GetBytes((ushort)record.Data.Length), 0, sizeof(ushort));
            macAlgo.Update(record.Data, 0, record.Length);

            return macAlgo.Digest();
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