using System;
using System.IO;
using Crypto.Encryption;
using Crypto.Encryption.Parameters;
using Crypto.Hashing;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    internal class BlockCipherStrategy : RecordStrategy
    {
        private long readSeqNum;
        private long writeSeqNum;

        public BlockCipherStrategy(TlsState state, Stream stream) : base(state, stream)
        {
        }

        private BlockCipherAdapter GetCipher()
        {
            var cipher = State.GetCipher();

            var adapter = cipher as BlockCipherAdapter;
            if (adapter != null)
            {
                return adapter;
            }

            // ReSharper disable SuspiciousTypeConversion.Global
            var blockCipher = cipher as IBlockCipher;
            if (blockCipher != null)
            {
                return new BlockCipherAdapter(blockCipher);
            }
            // ReSharper enable SuspiciousTypeConversion.Global

            throw new InvalidCastException("Cipher isn't a block cipher");
        }

        public override Record Read(RecordType type, TlsVersion version, ushort length)
        {
            var cipher = GetCipher();

            var blockLength = cipher.BlockLength;
            var iv = Reader.ReadBytes(blockLength);

            cipher.Init(new IVParameter(State.GetBlockCipherParameters(true), iv));

            var payload = Reader.ReadBytes(length - blockLength);
            var plaintext = new byte[payload.Length];

            cipher.Decrypt(payload, 0, plaintext, 0, payload.Length);

            var macAlgo = State.GetMAC(true);
            var macLength = macAlgo.HashSize / 8;
            var paddingLength = plaintext[plaintext.Length - 1];
            var contentLength = plaintext.Length - paddingLength - macLength - 1;
            SecurityAssert.SAssert(contentLength >= 0);

            //TODO constant time
            for (var i = plaintext.Length - 1; i > plaintext.Length - paddingLength; i--)
            {
                SecurityAssert.SAssert(plaintext[i] == paddingLength);
            }

            var mac = new byte[macLength];
            Array.Copy(plaintext, contentLength, mac, 0, macLength);

            var content = new byte[contentLength];
            Array.Copy(plaintext, 0, content, 0, content.Length);

            var computedMac = ComputeMAC(macAlgo, readSeqNum, type, version, content);

            SecurityAssert.HashAssert(mac, computedMac);

            readSeqNum++;

            return new Record(type, version, content);
        }

        public override void Write(RecordType type, TlsVersion version, byte[] data)
        {
            var cipher = GetCipher();

            var macAlgo = State.GetMAC(false);
            var mac = ComputeMAC(macAlgo, writeSeqNum, type, version, data);

            var iv = RandomGenerator.RandomBytes(cipher.BlockLength);

            var payloadLength = data.Length + macAlgo.HashSize / 8;

            var padding = (byte)(cipher.BlockLength - 1 - payloadLength % cipher.BlockLength);
            // TODO padding can be upto 255, so possible add more than the minimum

            payloadLength += padding + 1;

            var plaintext = new byte[payloadLength];
            var payload = new byte[payloadLength];

            var offset = 0;

            Array.Copy(data, 0, plaintext, offset, data.Length);
            offset += data.Length;

            Array.Copy(mac, 0, plaintext, offset, mac.Length);
            offset += mac.Length;

            for (; offset < payloadLength; offset++)
            {
                plaintext[offset] = padding;
            }

            cipher.Init(new IVParameter(State.GetBlockCipherParameters(false), iv));
            cipher.Encrypt(plaintext, 0, payload, 0, plaintext.Length);

            writeSeqNum++;

            Writer.Write(type);
            Writer.Write(version);
            Writer.Write((ushort)(iv.Length + payloadLength));
            Writer.Write(iv);
            Writer.Write(payload);
        }

        private byte[] ComputeMAC(IDigest macAlgo, long seqNum, RecordType type, TlsVersion version, byte[] content)
        {
            macAlgo.Update(EndianBitConverter.Big.GetBytes(seqNum), 0, sizeof(long));
            macAlgo.Update(new[] { (byte)type, version.Major, version.Major }, 0, 3);
            macAlgo.Update(EndianBitConverter.Big.GetBytes((ushort)content.Length), 0, sizeof(ushort));
            macAlgo.Update(content, 0, content.Length);

            return macAlgo.Digest();
        }
    }
}
