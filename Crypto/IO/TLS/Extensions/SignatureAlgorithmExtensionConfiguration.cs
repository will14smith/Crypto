namespace Crypto.IO.TLS.Extensions
{
    internal class SignatureAlgorithmExtensionConfiguration : TlsExtensionConfiguration
    {
        public override void Configure(TlsExtensionManager manager)
        {
            manager.RegisterHelloExtension(SignatureAlgorithmExtension.Type, Factory);
        }

        private static ITlsExtension Factory(TlsState state, byte[] helloData)
        {
            return new SignatureAlgorithmExtension(state, helloData);
        }
    }
}
