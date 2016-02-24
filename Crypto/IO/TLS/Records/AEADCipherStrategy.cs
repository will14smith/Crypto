﻿using System;
using System.IO;
using Crypto.Encryption;
using Crypto.Encryption.AEAD;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    internal class AEADCipherStrategy : RecordStrategy
    {
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
            var cipher = GetCipher().Cipher;

            // TODO parametrised from CipherSpec
            var explicitNonceLength = 8;

            var nonce = Reader.ReadBytes(explicitNonceLength);
            var payload = Reader.ReadBytes(length - explicitNonceLength);

            var aad = new byte[13];
            Array.Copy(EndianBitConverter.Big.GetBytes(State.ReadSeqNum++), 0, aad, 0, 8);
            Array.Copy(new[] { (byte)type, version.Major, version.Major }, 0, aad, 8, 3);
            Array.Copy(EndianBitConverter.Big.GetBytes((ushort)(length - explicitNonceLength - cipher.TagLength)), 0, aad, 11, 2);

            cipher.Init(State.GetAEADParameters(true, aad, nonce));

            var plaintext = new byte[payload.Length - cipher.TagLength];
            var plaintextLength = cipher.Decrypt(payload, 0, plaintext, 0, payload.Length - cipher.TagLength);
            plaintextLength += cipher.DecryptFinal(payload, plaintextLength, plaintext, plaintextLength);

            Array.Resize(ref plaintext, plaintextLength);

            return new Record(type, version, plaintext);
        }

        public override void Write(RecordType type, TlsVersion version, byte[] data)
        {
            var cipher = GetCipher().Cipher;

            // TODO parametrised from CipherSpec
            var explicitNonceLength = 8;
            var nonce = RandomGenerator.RandomBytes(explicitNonceLength);

            var aad = new byte[13];
            Array.Copy(EndianBitConverter.Big.GetBytes(State.WriteSeqNum++), 0, aad, 0, 8);
            Array.Copy(new[] { (byte)type, version.Major, version.Major }, 0, aad, 8, 3);
            Array.Copy(EndianBitConverter.Big.GetBytes((ushort)data.Length), 0, aad, 11, 2);

            var payload = new byte[explicitNonceLength + data.Length + cipher.TagLength];
            Array.Copy(nonce, payload, explicitNonceLength);

            cipher.Init(State.GetAEADParameters(false, aad, nonce));

            var payloadLength = explicitNonceLength;
            payloadLength += cipher.Encrypt(data, 0, payload, payloadLength, data.Length);
            payloadLength += cipher.EncryptFinal(payload, payloadLength);

            Writer.Write(type);
            Writer.Write(version);
            Writer.Write((ushort)payloadLength);
            Writer.Write(payload, 0, payloadLength);
        }
    }
}
