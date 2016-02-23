using System;
using System.IO;
using Crypto.Certificates;
using Crypto.IO.TLS.Messages;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    // https://tools.ietf.org/html/rfc5246#appendix-A
    public class TlsStream : Stream
    {
        private readonly TlsState state;
        private readonly TlsDispatcher dispatcher;

        public TlsStream(Stream inner)
        {
            SecurityAssert.NotNull(inner);
            SecurityAssert.SAssert(inner.CanRead);
            SecurityAssert.SAssert(inner.CanWrite);

            state = new TlsState(inner);
            dispatcher = new TlsDispatcher(state);
        }

        public CertificateManager Certificates => state.Certificates;

        public override bool CanRead => true;
        public override bool CanWrite => true;

        public void AuthenticateAsServer()
        {
            dispatcher.AuthenticateAsServer();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return dispatcher.ReadApplicationData(buffer, offset, count);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            dispatcher.WriteApplicationData(buffer, offset, count);
        }

        public override void Flush()
        {
            state.Flush();
        }

        public override void Close()
        {
            dispatcher.SendAlert(AlertLevel.Warning, AlertDescription.CloseNotify);

            base.Close();
        }

        #region unsupported

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override bool CanSeek => false;

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        #endregion
    }
}