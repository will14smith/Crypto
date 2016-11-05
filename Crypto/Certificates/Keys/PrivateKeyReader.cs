using System;
using System.IO;
using Crypto.ASN1;
using Crypto.Utils;

namespace Crypto.Certificates.Keys
{
    public class PrivateKeyReader
    {
        private readonly byte[] input;

        public PrivateKeyReader(byte[] input)
        {
            this.input = input;
        }

        public PrivateKey ReadKey()
        {
            var readerFactories = KeyReaderRegistry.GetPrivateReaders();

            foreach (var readerFactory in readerFactories)
            {
                var reader = readerFactory();

                var result = reader.TryRead(input);
                if (result.HasValue)
                {
                    return result.Value;
                }
            }

            throw new FormatException("Unable to read key");
        }
    }
}
