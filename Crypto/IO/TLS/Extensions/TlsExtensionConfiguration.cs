namespace Crypto.IO.TLS.Extensions
{
    public abstract class TlsExtensionConfiguration
    {
        /// <summary>
        /// Called when the extension is registered
        /// </summary>
        public abstract void Configure(TlsExtensionManager manager);
    }
}
