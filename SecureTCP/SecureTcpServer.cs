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
        private Dictionary<string, (Connection c, object keys)> connections;
        private RSA certificate;
        private Aes aes;
        private bool requireCertificate = false;
        private int port;
        private string ip;

        public bool running { get; private set; } = false;
        public string IpPort { get { return ip + ":" + port; } }
        public EncryptionSettings EncryptionSettings { get; private set; } = new EncryptionSettings();

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
                    Connection connection = new Connection(socket, EncryptionSettings);
                    EstablishConnection(connection);
                }
                catch (Exception) { }
            }
        }

        private void EstablishConnection(Connection connection)
        {
            short aesKeySize = EncryptionSettings.AesKeySize;
            short rsaKeySize = EncryptionSettings.RsaKeySize;

            RSA signer = RSA.Create(rsaKeySize);
            string publicXML = signer.ToXmlString(false);
            byte[] xmlBytes = Encoding.ASCII.GetBytes(publicXML);

            short certSigLength = certificate == null ? (short)0 : (short)(64 + certificate.KeySize / 8);

            byte[] unsignedMsg1 = new byte[6 + xmlBytes.Length + certSigLength];

            byte[] rsaSizeBytes = BitConverter.GetBytes(rsaKeySize);
            byte[] aesSizeBytes = BitConverter.GetBytes(aesKeySize);
            byte[] xmlByteLength = BitConverter.GetBytes((short)xmlBytes.Length);
            Array.Copy(rsaSizeBytes, 0, unsignedMsg1, 0, 2);
            Array.Copy(aesSizeBytes, 0, unsignedMsg1, 2, 2);
            Array.Copy(xmlBytes, 0, unsignedMsg1, 4, xmlBytes.Length);

            //Sign with certificate
            if (certificate != null)
            {
                byte[] messageHash = SHA512.Create().ComputeHash(unsignedMsg1);
                byte[] signature = certificate.SignHash(messageHash, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

                Array.Copy(messageHash, 0, unsignedMsg1, unsignedMsg1.Length - messageHash.Length - signature.Length, 64);
                Array.Copy(signature, 0, unsignedMsg1, unsignedMsg1.Length - signature.Length, signature.Length);
            }
            else
                unsignedMsg1[0] = 0;

            connection.Send(unsignedMsg1, false);



            //
            connection.DataReceived += (s, e) => { MessageReceived(this, new MessageReceivedEventArgs(s as Connection, e.Data)); };
            //ClientConnected(this, new ClientConnectedEventArgs(connection));
            connection.BeginReceiving();
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
            /*foreach (Connection connection in connections.Keys)
            {
                Send(data, connection);
            }*/
        }

        public void Stop()
        {
            server.Stop();
            running = false;
            connections.Clear();
        }

        public void DisconnectAll()
        {
            /*foreach (Connection connection in connections.Keys)
            {
                connection.ShutDown();
            }*/
        }
    }
}