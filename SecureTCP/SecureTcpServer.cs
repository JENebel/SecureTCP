using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;

namespace SecureTCP
{
    public class SecureTcpServer
    {
        private TcpListener server;
        private List<Connection> connections;
        private RSA certificate;
        private Aes aes;
        private bool requireCertificate = false;
        private int port;
        private string ip;

        public bool running { get; private set; } = false;
        public string IpPort { get { return ip + ":" + port; } }

        public event EventHandler<ClientConnectedEventArgs> ClientConnected;
        public event EventHandler<ClientDisconnectedEventArgs> ClientDisconnected;
        public event EventHandler<MessageReceivedEventArgs> MessageReceived;

        public SecureTcpServer(string ip, int port, string xmlString = "")
        {
            this.ip = ip;
            this.port = port;

            if (xmlString != "")
            {
                certificate = new RSACryptoServiceProvider();
                certificate.FromXmlString(xmlString);
            }
        }

        public void Start()
        {
            server = new TcpListener(new IPEndPoint(IPAddress.Parse(ip), port));
            running = true;
            server.Start();
            Listen();
        }

        private async void Listen()
        {
            while (running)
            {
                try
                {
                    Socket socket = await server.AcceptSocketAsync();
                    Connection connection = new Connection(socket);
                    EstablishConnection(connection);
                }
                catch (Exception) { }
            }
        }

        private async void EstablishConnection(Connection connection)
        {
            Console.WriteLine(connection.RemoteIpPort);
            RSA rsa = RSA.Create(4096);

            //Receive validateRequest
            byte[] req = await connection.Receive(1);
            if (requireCertificate)
            {
                if (req[0] == 0)
                {
                    //Not requesting, just sending public key
                    byte[] certificatePublic = Encoding.ASCII.GetBytes(certificate.ToXmlString(false));
                    connection.Send(certificatePublic, false);
                }
                else
                {
                    //Requesting, signing request
                    byte[] inputBytes = await connection.Receive(certificate.KeySize);
                    byte[] signature = certificate.SignData(inputBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    connection.Send(signature, false);
                }
            }

            //Receive RSA
            byte[] rawSignature = await connection.Receive(755);
            verifier = new RSACryptoServiceProvider();
            verifier.FromXmlString(Encoding.ASCII.GetString(rawSignature));
            //Send RSA
            byte[] rsaXml = Encoding.ASCII.GetBytes(rsa.ToXmlString(false));
            connection.Send(rsaXml, false);

            //Receive encrypted AES key
            byte[] rawAesKey = await connection.Receive(544);
            byte[] aesKey = Security.VerifiedData(verifier, rawAesKey);
            aes = Aes.Create();
            aes.Key = aesKey;

            //Send OK
            connection.Send(new byte[1], false);

            connection.DataReceived += (s, e) => { MessageReceived(this, new MessageReceivedEventArgs(s as Connection, e.Data)); };
            ClientConnected(this, new ClientConnectedEventArgs(connection));
            connection.BeginReceive();

            
        }

        public void Send(byte[] data, Connection connection)
        {
            try
            {
                connection.Send(data);
            }
            catch (Exception)
            {

                connection.ShutDown();
                ClientDisconnected(this, new ClientDisconnectedEventArgs(connection, DisconnectReason.Error));
            }
        }

        public void BroadCast(byte[] data)
        {
            foreach (Connection connection in connections.Keys)
            {
                Send(data, connection);
            }
        }

        public void Stop()
        {
            server.Stop();
            running = false;
            connections.Clear();
        }

        public void DisconnectAll()
        {
            foreach (Connection connection in connections.Keys)
            {
                connection.ShutDown();
            }
        }
    }
}