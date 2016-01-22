using System;
using System.IO;
using Crypto.IO.TLS.Messages;
using Crypto.Utils;

namespace Crypto.IO.TLS
{
    // https://tools.ietf.org/html/rfc5246#appendix-A
    public class TlsStream : Stream
    {
        private readonly TlsState state;

        public TlsStream(Stream inner)
        {
            SecurityAssert.NotNull(inner);
            SecurityAssert.SAssert(inner.CanRead);
            SecurityAssert.SAssert(inner.CanWrite);

            this.state = new TlsState(inner);
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;

        public void AuthenticateAsServer()
        {
            // Read ClientHello
            var message = (ClientHelloMessage)new HandshakeReader(state).Read();

            // build ServerHello

            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override void Flush()
        {
            state.Flush();
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