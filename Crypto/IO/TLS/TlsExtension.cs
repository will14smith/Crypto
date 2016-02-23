namespace Crypto.IO.TLS
{
    public abstract class TlsExtension
    {
        /// <summary>
        /// called when the extension is registered
        /// </summary>
        public abstract void Init(TlsExtensionManager manager);
    }
}
