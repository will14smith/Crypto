using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using Crypto.Certificates;
using Crypto.IO.TLS;

namespace Crypto.Client
{
    class Program
    {
        static void Main(string[] args)
        {
            var pemCert = File.ReadAllBytes("localhost.cert");
            var reader = new X509Reader(pemCert);
            var cert = reader.ReadCertificate();
            


            var server = new TcpListener(IPAddress.Any, 443);
            server.Start();

            Console.WriteLine("Listening for clients on {0}", server.LocalEndpoint);

            while (true)
            {
                var client = server.AcceptTcpClient();
                var clientStream = client.GetStream();

                Console.WriteLine("Client connected: " + client.Client.RemoteEndPoint);

                var tlsStream = new TlsStream(clientStream);

                tlsStream.AddCertificate(File.ReadAllBytes("localhost.cert"));
                tlsStream.AddPrivateKey(File.ReadAllBytes("localhost.key"));

                Console.WriteLine("Starting TLS connection");
                tlsStream.AuthenticateAsServer();

                client.Close();
            }
        }
    }
}
