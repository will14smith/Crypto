using System;
using System.Collections.Generic;
using System.Linq;
using Crypto.Encryption;
using Crypto.Hashing;
using Crypto.IO.TLS.Messages.Handshake;
using Crypto.Utils;

namespace Crypto.IO.TLS.Extensions
{
    public class SignatureAlgorithmExtension : ITlsExtension
    {
        public const ushort Type = 0x000d;

        private readonly TlsState state;

        private readonly List<Tuple<TlsHashAlgorithm, TlsSignatureAlgorithm>> algorithms = new List<Tuple<TlsHashAlgorithm, TlsSignatureAlgorithm>>();

        public SignatureAlgorithmExtension(TlsState state, byte[] helloData)
        {
            this.state = state;

            ReadData(helloData);
        }

        private void ReadData(byte[] data)
        {
            var length = EndianBitConverter.Big.ToUInt16(data, 0);
            SecurityAssert.SAssert(length % 2 == 0 && length >= 4);

            var count = length / 2;
            for (var i = 0; i < count; i++)
            {
                var hash = (TlsHashAlgorithm)data[2 * i + 2];
                var sig = (TlsSignatureAlgorithm)data[2 * i + 3];

                algorithms.Add(Tuple.Create(hash, sig));
            }
        }

        public HelloExtension GenerateHello()
        {
            if (state.ConnectionEnd == ConnectionEnd.Server)
            {
                return null;
            }

            throw new NotImplementedException();
        }

        private Tuple<TlsHashAlgorithm, TlsSignatureAlgorithm> SelectAlgorithm()
        {
            return algorithms
                .Where(algorithm => CipherSuiteExtensions.IsSupported(algorithm.Item1))
                .FirstOrDefault(algorithm => CipherSuiteExtensions.IsSupported(algorithm.Item2));
        }

        public TlsSignatureAlgorithm GetSignatureAlgorithm()
        {
            var algo = SelectAlgorithm();
            if (algo == null)
            {
                throw new InvalidOperationException("No supported algorithms");
            }

            return algo.Item2;
        }
        public TlsHashAlgorithm GetDigestAlgorithm()
        {
            var algo = SelectAlgorithm();
            if (algo == null)
            {
                throw new InvalidOperationException("No supported algorithms");
            }

            return algo.Item1;
        }
    }
}