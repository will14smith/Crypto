using System;
using System.IO;
using Crypto.Encryption;
using Crypto.Encryption.AEAD;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    internal class AEADCipherStrategy : RecordStrategy
    {
        private long readSeqNum;
        private long writeSeqNum;

        public AEADCipherStrategy(TlsState state, Stream stream) : base(state, stream)
        {
        }

        private AEADCipherAdapter GetCipher()
        {
            var cipher = State.GetCipher();

            var adapter = cipher as AEADCipherAdapter;
            if (adapter != null)
            {
                return adapter;
            }

            // ReSharper disable SuspiciousTypeConversion.Global
            var aeadCipher = cipher as IAEADBlockCipher;
            if (aeadCipher != null)
            {
                return new AEADCipherAdapter(aeadCipher);
            }
            // ReSharper enable SuspiciousTypeConversion.Global

            throw new InvalidCastException("Cipher isn't an AEAD cipher");
        }

        public override Record Read(RecordType type, TlsVersion version, ushort length)
        {
            var cipher = GetCipher();

            // TODO parametrised from CipherSpec
            var explicitNonceLength = 8;

            var nonce = Reader.ReadBytes(explicitNonceLength);
            var payload = Reader.ReadBytes(length - explicitNonceLength);

            var aad = new byte[13];
            Array.Copy(EndianBitConverter.Big.GetBytes(readSeqNum), 0, aad, 0, 8);
            Array.Copy(new[] { (byte)type, version.Major, version.Major }, 0, aad, 8, 3);
            Array.Copy(EndianBitConverter.Big.GetBytes((ushort)(length - explicitNonceLength - cipher.TagLength)), 0, aad, 11, 2);

            cipher.Init(State.GetAEADParameters(true, aad, nonce));

            var plaintext = new byte[payload.Length];
            var plaintextLength = cipher.Cipher.Decrypt(payload, 0, plaintext, 0, payload.Length);
            plaintextLength += cipher.Cipher.DecryptFinal(plaintext, plaintextLength);

            Array.Resize(ref plaintext, plaintextLength);

            readSeqNum++;

            return new Record(type, version, plaintext);
        }

        public override void Write(RecordType type, TlsVersion version, byte[] data)
        {
            var cipher = GetCipher();

            // TODO parametrised from CipherSpec
            var explicitNonceLength = 8;
            var nonce = RandomGenerator.RandomBytes(explicitNonceLength);

            var aad = new byte[13];
            Array.Copy(EndianBitConverter.Big.GetBytes(writeSeqNum), 0, aad, 0, 8);
            Array.Copy(new[] { (byte)type, version.Major, version.Major }, 0, aad, 8, 3);
            Array.Copy(EndianBitConverter.Big.GetBytes((ushort)data.Length), 0, aad, 11, 2);

            var payload = new byte[8 + data.Length + cipher.BlockLength];
            Array.Copy(nonce, payload, explicitNonceLength);

            cipher.Init(State.GetAEADParameters(false, aad, nonce));
            cipher.Encrypt(data, 0, payload, explicitNonceLength, data.Length);

            writeSeqNum++;

            Writer.Write(type);
            Writer.Write(version);
            Writer.Write((ushort)payload.Length);
            Writer.Write(payload);
        }
    }
}
