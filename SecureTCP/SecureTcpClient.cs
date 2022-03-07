using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SecureTCP
{
    public class SecureTcpClient
    {
        private Connection connection;

        public string ServerIpPort { get { return connection.RemoteIpPort; } }
        public bool Connected { get; private set; }

        public event EventHandler<ClientConnectedEventArgs> ClientConnected;
        public event EventHandler<ClientDisconnectedEventArgs> ClientDisconnected;
        public event EventHandler<MessageReceivedEventArgs> MessageReceived;

        public void Connect(string connectionString)
        {
            byte[] connectionData = Convert.FromBase64String(connectionString);
            byte[] ipBytes = connectionData.Take(4).ToArray();
            string ipString = ipBytes[0] + "." + ipBytes[1] + "." + ipBytes[2] + "." + ipBytes[3];

            byte[] portBytes = connectionData.Skip(4).Take(2).ToArray();
            ushort port = BitConverter.ToUInt16(portBytes);
            byte[] certKey = connectionData.Skip(6).ToArray();

            if (certKey.Length == 0) Connect(ipString, port);
            else Connect(ipString, port, certKey);
        }

        public void Connect(string ip, ushort port)
        {
            Connect(ip, port, null);
        }

        private async void Connect(string ip, ushort port, byte[] publicCertificateKey)
        {
            if (Connected) throw new Exception("Already connected");
            try
            {
                Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(IPAddress.Parse(ip), port);
                connection = new Connection(socket);

                //Receive serverHello
                byte[] serverHello = connection.ReceiveOnceAsync();
                EncryptionSettings ES = EncryptionSettings.FromBytes(serverHello.Take(2).ToArray());
                short keyLength = BitConverter.ToInt16(serverHello, 2);
                byte[] serverPubKey = serverHello.Skip(4).Take(keyLength).ToArray();

                if (publicCertificateKey != null) // Check signature
                {
                    if (serverHello[4 + keyLength] == 1) // If certificate received
                    {
                        //Setup verifier
                        ECDsa verifier = ECDsa.Create();
                        ECParameters ecParams = new ECParameters();
                        ecParams.Q.X = publicCertificateKey.Take(publicCertificateKey.Length / 2).ToArray();
                        ecParams.Q.Y = publicCertificateKey.Skip(publicCertificateKey.Length / 2).ToArray();
                        ecParams.Curve = ECCurve.NamedCurves.brainpoolP512r1;
                        verifier.ImportParameters(ecParams);

                        //Get message hash & signature
                        byte[] signature = serverHello.Skip(5 + keyLength).ToArray();
                        byte[] serverHelloNoSignature = serverHello.Take(4 + keyLength).ToArray();
                        byte[] messageHash = SHA512.HashData(serverHelloNoSignature);

                        //Verify
                        if (!verifier.VerifyHash(messageHash, signature)) 
                            throw new BadSignatureException("Certificate signature verification failed");
                    }
                    else
                        throw new Exception("No certificate signature received");
                }

                ECDiffieHellman serverPub = ECDiffieHellman.Create();
                ECParameters verParams = new ECParameters();
                verParams.Q.X = serverPubKey.Take(serverPubKey.Length / 2).ToArray();
                verParams.Q.Y = serverPubKey.Skip(serverPubKey.Length / 2).ToArray();
                verParams.Curve = ES.ECCurve;
                serverPub.ImportParameters(verParams);

                //Send ClientHello
                ECDiffieHellman clientECDH = ECDiffieHellman.Create(ES.ECCurve);
                ECParameters clientPubParams = clientECDH.ExportParameters(false);
                byte[] paramX = clientPubParams.Q.X;
                byte[] paramY = clientPubParams.Q.Y;
                byte[] clientPubKey = new byte[paramX.Length + paramY.Length];
                Array.Copy(paramX, 0, clientPubKey, 0, paramX.Length);
                Array.Copy(paramY, 0, clientPubKey, paramX.Length, paramY.Length);

                connection.Send(clientPubKey, MessageType.Handshake);

                //Generate shared secret
                byte[] sharedSecret = clientECDH.DeriveKeyMaterial(serverPub.PublicKey);

                Aes aes = Aes.Create();
                aes.Key = sharedSecret.Take(ES.AesKeySize / 8).ToArray();

                connection.Crypto = new Crypto(aes, ECDsa.Create(clientECDH.ExportParameters(true)), ECDsa.Create(serverPub.ExportParameters(false)));



                Connected = true;
                connection.DataReceived += (s, e) => { MessageReceived(this, new MessageReceivedEventArgs((s as Connection).RemoteIpPort, e.Data)); };
                connection.Disconnected += (s, e) => {
                    Connected = false;
                    if (ClientDisconnected != null) ClientDisconnected(this, new ClientDisconnectedEventArgs(e.IpPort, e.DisconnectReason));
                };
                if (ClientConnected != null) ClientConnected(this, new ClientConnectedEventArgs(connection.RemoteIpPort));
                connection.BeginReceiving();
            }
            catch (Exception e)
            {
                throw new Exception("Could not connect: " + e.Message);
            }
        }

        public void Send(byte[] data)
        {
            if (!Connected) throw new Exception("Cannot send message when not connected");
            connection.Send(data, MessageType.Normal);
        }

        public void Disconnect()
        {
            if (Connected)
            {
                connection.ShutDown(DisconnectReason.Normal);
            }
        }
    }
}