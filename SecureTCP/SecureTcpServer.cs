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
        private ushort port;
        private string ip;

        public bool running { get; private set; } = false;
        public string IpPort { get { return ip + ":" + port; } }
        public EncryptionSettings EncryptionSettings { get; private set; } = new EncryptionSettings();

        public event EventHandler<ClientConnectedEventArgs> ClientConnected;
        public event EventHandler<ClientDisconnectedEventArgs> ClientDisconnected;
        public event EventHandler<MessageReceivedEventArgs> MessageReceived;

        public SecureTcpServer(string ip, ushort port)
        {
            this.ip = ip;
            this.port = port;
        }

        public SecureTcpServer(string ip, ushort port, byte[] rawCertificate, string password)
        {
            this.ip = ip;
            this.port = port;

            //Load certificate

            certificate = ECDsa.Create(ECCurve.NamedCurves.brainpoolP512r1);
            int ut;
            certificate.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), rawCertificate, out ut);
        }

        public byte[] ExportCertificate(string password)
        {
            PbeParameters pbeParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 10017);
            byte[] cert = certificate.ExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), pbeParams);
            return cert;
        }

        public string ExportConnectionString()
        {
            ECParameters ecParameters = certificate.ExportParameters(false);

            byte[] rawCS = new byte[6 + ecParameters.Q.X.Length * 2];

            ecParameters.Q.X.CopyTo(rawCS, 6);
            ecParameters.Q.Y.CopyTo(rawCS, 6 + ecParameters.Q.X.Length);

            var i = IPAddress.Parse(ip);
            byte[] ipBytes = new byte[4];
            int len;
            i.TryWriteBytes(ipBytes, out len);
            Array.Copy(ipBytes, 0, rawCS, 0, len);
            Array.Copy(BitConverter.GetBytes(port), 0, rawCS, 4, 2);

            return Convert.ToBase64String(rawCS);
        }

        public void Start(EncryptionSettings encryption)
        {
            EncryptionSettings = encryption;
            Start();
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
            //send ServerHello
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

            byte[] unsignedMsg = new byte[4 + serverPubKey.Length + 1];

            byte[] pubKeySizeBytes = BitConverter.GetBytes((short)serverPubKey.Length);

            Array.Copy(encryptionModeBytes, 0, unsignedMsg, 0, 2);
            Array.Copy(pubKeySizeBytes, 0, unsignedMsg, 2, 2);
            Array.Copy(serverPubKey, 0, unsignedMsg, 4, serverPubKey.Length);

            byte[] serverHello;
            //Sign with certificate
            if (certificate != null)
            {
                byte[] messageHash = SHA512.Create().ComputeHash(unsignedMsg.Take(unsignedMsg.Length - 1).ToArray());
                byte[] signature = certificate.SignHash(messageHash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

                serverHello = new byte[unsignedMsg.Length + signature.Length];

                Array.Copy(unsignedMsg, 0, serverHello, 0, unsignedMsg.Length);
                serverHello[unsignedMsg.Length - 1] = 1;
                Array.Copy(signature, 0, serverHello, unsignedMsg.Length, signature.Length);
            }
            else
                serverHello = unsignedMsg;

            connection.Send(serverHello, MessageType.Handshake);

            //Receive ClientHello
            byte[] clientHello = connection.ReceiveOnceAsync();
            ECDiffieHellman clientPub = ECDiffieHellman.Create();
            ECParameters verParams = new ECParameters();
            verParams.Q.X = clientHello.Take(clientHello.Length / 2).ToArray();
            verParams.Q.Y = clientHello.Skip(clientHello.Length / 2).ToArray();
            verParams.Curve = EncryptionSettings.ECCurve;
            clientPub.ImportParameters(verParams);

            //Generate shared secret
            byte[] sharedSecret = serverECDH.DeriveKeyMaterial(clientPub.PublicKey);

            Aes aes = Aes.Create();
            aes.Key = sharedSecret.Take(EncryptionSettings.AesKeySize / 8).ToArray();

            connection.Crypto = new Crypto(aes, ECDsa.Create(serverECDH.ExportParameters(true)), ECDsa.Create(clientPub.ExportParameters(false)));



            connection.DataReceived += (s, e) => { MessageReceived(this, new MessageReceivedEventArgs(s as Connection, e.Data)); };

            if(ClientConnected != null) ClientConnected(this, new ClientConnectedEventArgs(connection));
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