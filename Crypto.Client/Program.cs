using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using Crypto.Certificates;
using Crypto.Certificates.Keys;
using Crypto.ECGCM;
using Crypto.EllipticCurve;
using Crypto.GCM;
using Crypto.IO.TLS;
using Crypto.IO.TLS.Extensions;

namespace Crypto.Client
{
    class Program
    {
        static void Main(string[] args)
        {
            var server = new TcpListener(IPAddress.Any, 443);
            server.Start();
            
            TlsExtensionManager.RegisterExtension(new ECExtensionConfiguration());
            TlsExtensionManager.RegisterExtension(new GCMExtensionConfiguration());
            TlsExtensionManager.RegisterExtension(new ECGCMExtensionConfiguration());
            
            Console.WriteLine("Listening for clients on {0}", server.LocalEndpoint);

            var certReader = new X509Reader(File.ReadAllBytes("localhost_secp256k1.cert"));
            var cert = certReader.ReadCertificate();

            var keyReader = new PrivateKeyReader(File.ReadAllBytes("localhost_secp256k1.key"));
            var key = keyReader.ReadKey();

            while (true)
            {
                var client = server.AcceptTcpClient();
                var clientStream = client.GetStream();

                Console.WriteLine("Client connected: " + client.Client.RemoteEndPoint);

                var tlsStream = new TlsStream(clientStream);

                tlsStream.Certificates.AddCertificate(File.ReadAllBytes("localhost_secp256k1.cert"));
                tlsStream.Certificates.AddPrivateKey(File.ReadAllBytes("localhost_secp256k1.key"));

                //tlsStream.Certificates.AddCertificate(File.ReadAllBytes("localhost.cert"));
                //tlsStream.Certificates.AddPrivateKey(File.ReadAllBytes("localhost.key"));

                Console.WriteLine("Starting TLS connection");
                tlsStream.AuthenticateAsServer();

                var reader = new StreamReader(tlsStream);
                var writer = new StreamWriter(tlsStream);

                Console.WriteLine(reader.ReadLine());

                writer.WriteLine("HTTP/1.1 200 OK");
                writer.WriteLine("");
                writer.WriteLine("Hello browser!");
                writer.Flush();

                tlsStream.Close();
                client.Close();
            }
        }
    }
}
