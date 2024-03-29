﻿using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SecureTCP
{
    public class SecureTcpClient
    {
        private Connection connection;

        public string ServerIpPort { get { return connection.RemoteIpPort; } }
        public string LocalIpPort { get { return connection.LocalIpPort; } }
        public bool Connected { get; private set; }
        public bool Certified { get; private set; }

        public event EventHandler<ClientConnectedEventArgs> ClientConnected;
        public event EventHandler<ClientDisconnectedEventArgs> ClientDisconnected;
        public event EventHandler<MessageReceivedEventArgs> MessageReceived;
        public Func<byte[], string, byte[]> Respond { set { connection.Respond = value; } }

        public async Task Connect(string connectionString)
        {
            byte[] connectionData = Convert.FromBase64String(connectionString);
            byte[] ipBytes = connectionData.Take(4).ToArray();
            string ipString = ipBytes[0] + "." + ipBytes[1] + "." + ipBytes[2] + "." + ipBytes[3];

            byte[] portBytes = connectionData.Skip(4).Take(2).ToArray();
            ushort port = BitConverter.ToUInt16(portBytes);
            byte[] certKey = connectionData.Skip(6).ToArray();

            Task t = Connect(ipString, port, certKey.Length != 0 ? certKey : null);
            if (await Task.WhenAny(t, Task.Delay(3000)) != t)
            {
                throw new Exception("Connection attempt timed out");
            }
        }

        public async Task Connect(string ip, ushort port)
        {
            Task t = Connect(ip, port, null);
            if (await Task.WhenAny(t, Task.Delay(3000)) != t)
            {
                throw new Exception("Connection attempt timed out");
            }
        }

        private async Task Connect(string ip, ushort port, byte[] publicCertificateKey)
        {
            if (Connected) throw new Exception("Already connected");
            try
            {
                Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(IPAddress.Parse(ip), port);
                connection = new Connection(socket);
                Certified = false;

                //Send random data
                byte[] randData = RandomNumberGenerator.GetBytes(256);
                connection.Send(randData, MessageType.Handshake);

                //Receive serverHello
                byte[] serverHello = connection.ReceiveOnceAsync();
                EncryptionSettings ES = EncryptionSettings.FromBytes(serverHello.Take(2).ToArray());
                short keyLength = BitConverter.ToInt16(serverHello, 2);
                byte[] serverPubKey = serverHello.Skip(4).Take(keyLength).ToArray();

                if (publicCertificateKey != null) // Check signature
                {
                    if (serverHello[4 + keyLength + randData.Length] == 1) // If certificate received
                    {
                        //Setup verifier from connection string
                        ECDsa verifier = ECDsa.Create();
                        ECParameters ecParams = new ECParameters();
                        ecParams.Q.X = publicCertificateKey.Take(publicCertificateKey.Length / 2).ToArray();
                        ecParams.Q.Y = publicCertificateKey.Skip(publicCertificateKey.Length / 2).ToArray();
                        ecParams.Curve = ECCurve.NamedCurves.brainpoolP512r1;
                        verifier.ImportParameters(ecParams);

                        //Get message hash & signature
                        byte[] serverRandData = serverHello.Skip(4 + keyLength).Take(randData.Length).ToArray();
                        if(!serverRandData.SequenceEqual(randData))
                            throw new BadSignatureException("Random data doesn't match up");

                        byte[] serverHelloNoSignature = serverHello.Take(serverHello.Length - verifier.GetMaxSignatureSize(DSASignatureFormat.IeeeP1363FixedFieldConcatenation)).ToArray();
                        byte[] signature = serverHello.Skip(serverHelloNoSignature.Length).ToArray();
                        byte[] messageHash = SHA512.HashData(serverHelloNoSignature);

                        //Verify
                        if (!verifier.VerifyHash(messageHash, signature)) 
                            throw new BadSignatureException("Certificate signature verification failed");
                        Certified = true;
                    }
                    else
                        throw new BadSignatureException("No certificate signature received");
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
                connection.DataReceived += (s, e) => { if (MessageReceived != null) MessageReceived(this, new MessageReceivedEventArgs((s as Connection).RemoteIpPort, e.Data)); };
                connection.Disconnected += (s, e) => {
                    Connected = false;
                    if (ClientDisconnected != null) ClientDisconnected(this, e);
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

        public async Task<byte[]> SendAndWait(byte[] data)
        {
            return await connection.SendAndWait(data);
        }

        public void Disconnect()
        {
            if (Connected)
            {
                connection.ShutDown();
            }
        }
    }
}