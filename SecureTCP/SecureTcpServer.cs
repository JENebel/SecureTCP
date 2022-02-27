using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace SecureTCP
{
    public class SecureTcpServer
    {
        private TcpListener server;
        private Dictionary<string, (Connection c, object keys)> connections;
        private ECDsa certificate;
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

        public SecureTcpServer(string ip, int port)
        {
            this.ip = ip;
            this.port = port;
        }

        public SecureTcpServer(string ip, int port, byte[] rawCertificate, string password)
        {
            this.ip = ip;
            this.port = port;

            //Load certificate
            //PasswordDeriveBytes pdb = new PasswordDeriveBytes();
            byte[] certificate;
            ECParameters certParams = new ECParameters();
            byte[] x = new byte[rawCertificate.Length / 2];
            byte[] y = new byte[rawCertificate.Length / 2];
            Array.Copy(rawCertificate, 0, x, 0, x.Length);
            Array.Copy(rawCertificate, rawCertificate.Length / 2, y, 0, y.Length);
            certParams.Curve = ECCurve.NamedCurves.brainpoolP512r1; // SHOULD BE ABLE TO CHANGE
            certParams.Q.X = x;
            certParams.Q.Y = y;

            this.certificate = ECDsa.Create(certParams);

        }

        public byte[] ExportCertificate(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(8);

            var param = certificate.ExportParameters(true);
            byte[] QX = param.Q.X;
            byte[] QY = param.Q.Y;
            byte[] D = param.D;
            byte[] serialized = new byte[QX.Length + QY.Length + D.Length];
            Array.Copy(QX, serialized, D.Length);
            Array.Copy(QY, 0, serialized, QX.Length, QY.Length);
            Array.Copy(D, 0, serialized, QX.Length + QY.Length, D.Length);
            
            byte[] encrypted = new byte[16 + serialized.Length];
            Array.Copy(salt, encrypted, salt.Length);
            return serialized;
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
            ECCurve curve = EncryptionSettings.ECCurve;
            ECDiffieHellman serverECDH = ECDiffieHellman.Create(curve);
            
            ECParameters serverPubParams = serverECDH.ExportParameters(false);
            byte[] paramX = serverPubParams.Q.X;
            byte[] paramY = serverPubParams.Q.Y;
            byte[] serverPubKey = new byte[paramX.Length + paramY.Length];
            Array.Copy(paramX, 0, serverPubKey, 0, paramX.Length);
            Array.Copy(paramY, 0, serverPubKey, paramX.Length, paramY.Length);

            byte[] encryptionModeBytes = EncryptionSettings.ToBytes();

            byte[] unsignedMsg = new byte[6 + serverPubKey.Length + 1];

            byte[] pubKeySizeBytes = BitConverter.GetBytes(serverPubKey.Length);
            byte[] xmlByteLength = BitConverter.GetBytes((short)serverPubKey.Length);
            Array.Copy(encryptionModeBytes, 0, unsignedMsg, 0, 2);
            Array.Copy(pubKeySizeBytes, 0, unsignedMsg, 2, 2);
            Array.Copy(serverPubKey, 0, unsignedMsg, 4, serverPubKey.Length);

            byte[] serverHello;
            //Sign with certificate
            if (certificate != null)
            {
                byte[] messageHash = SHA512.Create().ComputeHash(unsignedMsg);
                byte[] signature = certificate.SignHash(messageHash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

                serverHello = new byte[unsignedMsg.Length + signature.Length];

                Array.Copy(unsignedMsg, 0, serverHello, 0, unsignedMsg.Length);
                serverHello[unsignedMsg.Length - 1] = 1;
                Array.Copy(signature, 0, serverHello, unsignedMsg.Length, signature.Length);
            }
            else
                serverHello = unsignedMsg;

            connection.Send(unsignedMsg, MessageType.Handshake);



            //
            connection.DataReceived += (s, e) => { MessageReceived(this, new MessageReceivedEventArgs(s as Connection, e.Data)); };
            //ClientConnected(this, new ClientConnectedEventArgs(connection));
            connection.BeginReceiving();
        }

        public void Send(byte[] data, Connection connection)
        {
            try
            {
                connection.Send(data, MessageType.Normal);
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

        public byte[] ConnectionString(bool includeCertificate)
        {
            if (certificate != null)
            {
                string xmlString = certificate.ToXmlString(false);
                
            }

            return null;
        }
    }
}