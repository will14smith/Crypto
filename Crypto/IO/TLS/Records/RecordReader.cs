using System;
using System.IO;
using Crypto.Encryption;
using Crypto.Encryption.Modes;
using Crypto.IO.TLS.Messages;
using Crypto.Utils;
using StreamReader = Crypto.Utils.IO.StreamReader;

namespace Crypto.IO.TLS
{
    public class RecordReader : StreamReader
    {
        private readonly TlsState state;

        public RecordReader(TlsState state, Stream stream) : base(stream)
        {
            this.state = state;
        }

        public Record ReadRecord()
        {
            return state.Protected ? ReadCipherText() : ReadPlainText();
        }

        private Record ReadCipherText()
        {
            var type = Reader.ReadRecordType();
            var version = Reader.ReadVersion();
            var length = Reader.ReadUInt16();
            byte[] data;

            var cipher = state.GetCipher();
            if (cipher is BlockModeCipher)
            {
                data = ReadBlockCipher((BlockModeCipher)cipher, length);
            }
            else
            {
                throw new NotImplementedException();
            }

            return new Record(type, version, data);
        }

        private byte[] ReadBlockCipher(BlockModeCipher cipher, ushort length)
        {
            var blockSize = cipher.Cipher.BlockSize;
            var iv = Reader.ReadBytes(blockSize);

            cipher.Mode.IV = iv;

            var hmac = state.GetHMAC();

            var payload = Reader.ReadBytes(length - blockSize);
            var plaintext = new byte[payload.Length];

            cipher.Decrypt(payload, 0, plaintext, 0, payload.Length);

            throw new NotImplementedException();
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