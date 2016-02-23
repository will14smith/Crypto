using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using Crypto.GCM;
using Crypto.IO.TLS;

namespace Crypto.Client
{
    class Program
    {
        static void Main(string[] args)
        {
            var server = new TcpListener(IPAddress.Any, 443);
            server.Start();
            
            // TODO...
            var tlsManager = new TlsExtensionManager();
            var gcmExtenion = new GCMExtension();
            gcmExtenion.Init(tlsManager);
            // END TODO...

            Console.WriteLine("Listening for clients on {0}", server.LocalEndpoint);

            while (true)
            {
                var client = server.AcceptTcpClient();
                var clientStream = client.GetStream();

                Console.WriteLine("Client connected: " + client.Client.RemoteEndPoint);

                var tlsStream = new TlsStream(clientStream);

                tlsStream.Certificates.AddCertificate(File.ReadAllBytes("localhost.cert"));
                tlsStream.Certificates.AddPrivateKey(File.ReadAllBytes("localhost.key"));

                Console.WriteLine("Starting TLS connection");
                tlsStream.AuthenticateAsServer();

                var reader = new StreamReader(tlsStream);
                var writer = new StreamWriter(tlsStream);

                // Console.WriteLine(reader.ReadLine());
                writer.WriteLine("World");
                writer.Flush();

                tlsStream.Close();
                client.Close();
            }
        }
    }
}
