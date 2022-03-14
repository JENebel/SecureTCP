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
        private Dictionary<string, Connection> clients;
        private ECDsa certificate;
        
        public bool Running { get; private set; } = false;
        public ushort Port { get; private set; }
        public string Ip { get; private set; }
        public string IpPort { get { return Ip + ":" + Port; } }
        public EncryptionSettings EncryptionSettings { get; private set; } = new EncryptionSettings();
        public string[] Clients { get { return clients.Keys.ToArray(); } }

        public event EventHandler<ClientConnectedEventArgs> ClientConnected;
        public event EventHandler<ClientDisconnectedEventArgs> ClientDisconnected;
        public event EventHandler<MessageReceivedEventArgs> MessageReceived;

        public SecureTcpServer(string ip, ushort port)
        {
            this.Ip = ip;
            this.Port = port;
        }

        public SecureTcpServer(string ip, ushort port, byte[] rawCertificate, string password)
        {
            this.Ip = ip;
            this.Port = port;

            //Load certificate

            certificate = ECDsa.Create(ECCurve.NamedCurves.brainpoolP512r1);
            int ut;
            certificate.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), rawCertificate, out ut);
        }

        public void GenerateCertificate()
        {
            certificate = ECDsa.Create(ECCurve.NamedCurves.brainpoolP512r1);
        }

        public byte[] ExportCertificate(string password)
        {
            PbeParameters pbeParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 10017);
            byte[] cert = certificate.ExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), pbeParams);
            return cert;
        }

        public string ExportConnectionString()
        {
            byte[] ipBytes = new byte[6];
            int len;
            var i = IPAddress.Parse(Ip);
            i.TryWriteBytes(ipBytes, out len);
            Array.Copy(BitConverter.GetBytes(Port), 0, ipBytes, 4, 2);
            if (certificate == null) return Convert.ToBase64String(ipBytes);

            ECParameters ecParameters = certificate.ExportParameters(false);

            byte[] rawCS = new byte[6 + ecParameters.Q.X.Length * 2];

            ecParameters.Q.X.CopyTo(rawCS, 6);
            ecParameters.Q.Y.CopyTo(rawCS, 6 + ecParameters.Q.X.Length);

            Array.Copy(ipBytes, 0, rawCS, 0, 6);

            return Convert.ToBase64String(rawCS);
        }

        public void Start(EncryptionSettings encryption)
        {
            EncryptionSettings = encryption;
            Start();
        }

        public void Start()
        {
            server = new TcpListener(new IPEndPoint(IPAddress.Parse(Ip), Port));
            clients = new();
            Running = true;
            server.Start();
            Listen();
        }

        private async void Listen()
        {
            while (Running)
            {
                try
                {
                    Socket socket = await server.AcceptSocketAsync();
                    Connection connection = new Connection(socket);
                    EstablishConnection(connection);
                    connection.BeginReceiving();
                }
                catch { }
            }
        }

        private void EstablishConnection(Connection connection)
        {
            //Receive RandData
            byte[] randData = connection.ReceiveOnceAsync();

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

            byte[] unsignedMsg = new byte[4 + serverPubKey.Length + randData.Length + 1];

            byte[] pubKeySizeBytes = BitConverter.GetBytes((short)serverPubKey.Length);

            Array.Copy(encryptionModeBytes, 0, unsignedMsg, 0, 2);
            Array.Copy(pubKeySizeBytes, 0, unsignedMsg, 2, 2);
            Array.Copy(serverPubKey, 0, unsignedMsg, 4, serverPubKey.Length);
            Array.Copy(randData, 0, unsignedMsg, 4 + serverPubKey.Length, randData.Length);

            byte[] serverHello;
            //Sign with certificate
            if (certificate != null)
            {
                unsignedMsg[unsignedMsg.Length - 1] = 1;

                byte[] messageHash = SHA512.Create().ComputeHash(unsignedMsg);
                byte[] signature = certificate.SignHash(messageHash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

                serverHello = new byte[unsignedMsg.Length + signature.Length];

                Array.Copy(unsignedMsg, 0, serverHello, 0, unsignedMsg.Length);
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


            clients.Add(connection.RemoteIpPort, connection);

            connection.DataReceived += (s, e) => { MessageReceived(this, new MessageReceivedEventArgs((s as Connection).RemoteIpPort, e.Data)); };
            if(ClientConnected != null) ClientConnected(this, new ClientConnectedEventArgs(connection.RemoteIpPort));
            connection.Disconnected += (s, e) => {
                clients.Remove(connection.RemoteIpPort);
                if (ClientDisconnected != null) ClientDisconnected(this, e);
            };
        }

        public void Send(byte[] data, string ipPort)
        {
            Send(data, clients[ipPort]);
        }

        private void Send(byte[] data, Connection client)
        {
            client.Send(data, MessageType.Normal);
        }

        public void BroadCast(byte[] data)
        {
            foreach (Connection client in clients.Values)
            {
                Send(data, client);
            }
        }

        public void Stop()
        {
            server.Stop();
            Running = false;
            DisconnectAll();
            clients.Clear();
        }

        public void DisconnectAll()
        {
            foreach (string ipPort in Clients)
            {
                Disconnect(ipPort);
            }
        }

        public void Disconnect(string ipPort)
        {
            clients[ipPort].ShutDown();
            clients.Remove(ipPort);
        }
    }
}