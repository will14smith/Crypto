using System;
using Crypto.Encryption;
using Crypto.Hashing;
using Crypto.IO.Signing;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    public static class SignedStreamExtensions
    {
        public static void WriteTlsSignature(this SignedStream stream)
        {
            var hashAlgo = GetHashEnum(stream.HashAlgorithm);
            var signAlgo = GetSignatureEnum(stream.SignatureAlgorithm);

            stream.InnerStream.Write(new[] { hashAlgo, signAlgo }, 0, 2);

            var signature = stream.Sign();

            stream.InnerStream.Write(EndianBitConverter.Big.GetBytes((ushort)signature.Length), 0, 2);
            stream.InnerStream.Write(signature, 0, signature.Length);
        }

        private static byte GetHashEnum(IDigest digest)
        {
            if (digest is NullDigest) return 0;
            if (digest is MD5Digest) return 1;
            if (digest is SHA1Digest) return 2;
            if (digest is SHA256Digest) return 4;

            throw new NotSupportedException();
        }
        private static byte GetSignatureEnum(ISignatureCipher signatureCipher)
        {
            if (signatureCipher is NullCipher) return 0;
            if (signatureCipher is RSA) return 1;

            throw new NotSupportedException();
        }
    }
}
