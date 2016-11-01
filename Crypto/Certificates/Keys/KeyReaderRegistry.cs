using System;
using System.Collections.Generic;
using Crypto.ASN1;

namespace Crypto.Certificates.Keys
{
    public class KeyReaderRegistry
    {
        private static readonly Dictionary<string, Func<IPublicKeyReader>> PublicKeyReaders;

        static KeyReaderRegistry()
        {
            PublicKeyReaders = new Dictionary<string, Func<IPublicKeyReader>>();

            Register(WellKnownObjectIdentifiers.RSAEncryption, () => new RSAKeyReader());
        }

        public static void Register(ASN1ObjectIdentifier algorithm, Func<IPublicKeyReader> factory)
        {
            var identifier = algorithm.Identifier;
            if (PublicKeyReaders.ContainsKey(identifier))
            {
                throw new InvalidOperationException("Algorithm already registered");
            }

            PublicKeyReaders.Add(identifier, factory);
        }


        internal static IPublicKeyReader GetPublicReader(ASN1ObjectIdentifier algorithm)
        {
            return PublicKeyReaders[algorithm.Identifier]();
        }
    }
}