using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SecureTCP
{
    public class SecureTcpClient
    {
        private Connection connection;
        private RSA verifier;
        private RSA rsa;
        private Aes aes;
        private RSA certificate;
        private bool requireCertificate;

        public string ServerIpPort { get { return connection.RemoteIpPort; } }
        public bool Connected { get; private set; }

        public event EventHandler<ClientConnectedEventArgs> ClientConnected;
        public event EventHandler<ClientDisconnectedEventArgs> ClientDisconnected;
        public event EventHandler<MessageReceivedEventArgs> MessageReceived;

        public SecureTcpClient(bool requireCertificate = false)
        {
            this.requireCertificate = requireCertificate;
        }

        public async void ConnectAsync(string ipPort, RSA serverCertificate = null)
        {
            try
            {
                string[] split = ipPort.Split(':');
                string ip = split[0];
                int port = int.Parse(split[1]);
                certificate = serverCertificate;

                Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(IPAddress.Parse(ip), port);
                connection = new Connection(socket);
                rsa = RSA.Create(4096);
                aes = Aes.Create();
                aes.KeySize = 256;
                aes.GenerateKey();

                if (requireCertificate)
                {
                    if (certificate == null)
                    {
                        //Get certificate
                        connection.Send(new byte[] { 0 }, false);
                        byte[] rawCertificate = await connection.Receive(2803);
                        certificate = new RSACryptoServiceProvider();
                        certificate.FromXmlString(Encoding.ASCII.GetString(rawCertificate));
                    }
                    else
                    {
                        //Validate server certificate
                        connection.Send(new byte[] { 1 }, false);
                        byte[] randBytes = RandomNumberGenerator.GetBytes(certificate.KeySize);
                        connection.Send(randBytes, false);
                        byte[] signature = await connection.Receive(2048);
                        bool valid = certificate.VerifyData(randBytes, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                        if (!valid) throw new BadSignatureException("Certificate invalid");
                    }
                }

                //Send RSA
                byte[] rsaXml = Encoding.ASCII.GetBytes(rsa.ToXmlString(false));
                connection.Send(rsaXml, false);

                //Receive RSA
                byte[] rawSignature = await connection.Receive(755);
                verifier = new RSACryptoServiceProvider();
                verifier.FromXmlString(Encoding.ASCII.GetString(rawSignature));

                //Send incrypted AES key
                byte[] message = Security.SignData(rsa, aes.Key);
                connection.Send(message, false);

                //Receive Ok
                await connection.Receive(1);
                Connected = true;
                ClientConnected(this, new ClientConnectedEventArgs(connection));
                connection.DataReceived += (s, e) => { MessageReceived(this, new MessageReceivedEventArgs(s as Connection, e.Data)); };
                connection.BeginReceive();
            }
            catch (Exception e)
            {
                throw new Exception("Could not connect: " + e.Message);
            }
        }

        public void Send(byte[] data)
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
    }
}