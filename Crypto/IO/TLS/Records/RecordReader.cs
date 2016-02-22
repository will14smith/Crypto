using System;
using System.IO;
using Crypto.Encryption;
using Crypto.Encryption.Parameters;
using Crypto.Hashing;
using Crypto.Utils;
using StreamReader = Crypto.Utils.IO.StreamReader;

namespace Crypto.IO.TLS
{
    public class RecordReader : StreamReader
    {
        private readonly TlsState state;
        private long seqNum;

        public RecordReader(TlsState state, Stream stream) : base(stream)
        {
            this.state = state;
        }

        public Record ReadRecord()
        {
            return state.ReadProtected ? ReadCipherText() : ReadPlainText();
        }

        private Record ReadCipherText()
        {
            var type = Reader.ReadRecordType();
            var version = Reader.ReadVersion();
            var length = Reader.ReadUInt16();
            byte[] data;

            var cipher = state.GetCipher();
            if (cipher is BlockCipherAdapter)
            {
                data = ReadBlockCipher((BlockCipherAdapter)cipher, type, version, length);
            }
            else if (cipher is AEADCipherAdapter)
            {
                data = ReadAEADCipher((AEADCipherAdapter)cipher, type, version, length);
            }
            else
            {
                throw new NotImplementedException();
            }

            return new Record(type, version, data);
        }

        private byte[] ReadBlockCipher(BlockCipherAdapter cipher, RecordType type, TlsVersion version, ushort length)
        {
            var blockLength = cipher.BlockLength;
            var iv = Reader.ReadBytes(blockLength);

            cipher.Init(new IVParameter(state.GetBlockCipherParameters(true), iv));

            var payload = Reader.ReadBytes(length - blockLength);
            var plaintext = new byte[payload.Length];

            cipher.Decrypt(payload, 0, plaintext, 0, payload.Length);

            var macAlgo = state.GetMAC(true);
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

            var computedMac = ComputeMAC(macAlgo, seqNum, type, version, content);

            SecurityAssert.HashAssert(mac, computedMac);

            seqNum++;

            return content;
        }

        private byte[] ComputeMAC(IDigest macAlgo, long seqNum, RecordType type, TlsVersion version, byte[] content)
        {
            macAlgo.Update(EndianBitConverter.Big.GetBytes(seqNum), 0, sizeof(long));
            macAlgo.Update(new[] { (byte)type, version.Major, version.Major }, 0, 3);
            macAlgo.Update(EndianBitConverter.Big.GetBytes((ushort)content.Length), 0, sizeof(ushort));
            macAlgo.Update(content, 0, content.Length);

            return macAlgo.Digest();
        }

        private byte[] ReadAEADCipher(AEADCipherAdapter cipher, RecordType type, TlsVersion version, ushort length)
        {
            // TODO parametrised from CipherSpec
            var explicitNonceLength = 8;

            var nonce = Reader.ReadBytes(explicitNonceLength);
            var payload = Reader.ReadBytes(length - explicitNonceLength);

            var aad = new byte[13];
            Array.Copy(EndianBitConverter.Big.GetBytes(seqNum), 0, aad, 0, 8);
            Array.Copy(new[] { (byte)type, version.Major, version.Major }, 0, aad, 8, 3);
            Array.Copy(EndianBitConverter.Big.GetBytes((ushort)(length - explicitNonceLength - cipher.TagLength)), 0, aad, 11, 2);

            cipher.Init(state.GetAEADParameters(true, aad, nonce));

            var plaintext = new byte[payload.Length];
            var plaintextLength = cipher.Cipher.Decrypt(payload, 0, plaintext, 0, payload.Length);
            plaintextLength += cipher.Cipher.DecryptFinal(plaintext, plaintextLength);

            Array.Resize(ref plaintext, plaintextLength);

            seqNum++;

            return plaintext;
        }

        private Record ReadPlainText()
        {
            var type = Reader.ReadRecordType();
            var version = Reader.ReadVersion();
            var length = Reader.ReadUInt16();

            SecurityAssert.SAssert(length <= 0x4000);

            var data = Reader.ReadBytes(length);

            return new Record(type, version, data);
        }
    }
}