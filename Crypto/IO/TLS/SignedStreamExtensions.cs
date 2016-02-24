using System;
using Crypto.Encryption;
using Crypto.Hashing;
using Crypto.IO.Signing;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public static class SignedStreamExtensions
    {
        public static void WriteTlsSignature(this SignedStream stream, TlsState state)
        {
            var algos = state.GetSigningAlgorithms();

            var hashAlgo = algos.Item1;
            var signAlgo = algos.Item2;

            stream.InnerStream.Write(new[] { hashAlgo.Id, signAlgo.Id }, 0, 2);

            var signature = stream.Sign();

            stream.InnerStream.Write(EndianBitConverter.Big.GetBytes((ushort)signature.Length), 0, 2);
            stream.InnerStream.Write(signature, 0, signature.Length);
        }
    }
}
