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

        public void Connect(string connectionString, bool a)
        {
            throw new NotImplementedException();
        }

        public void Connect(string ipPort)
        {
            Connect(ipPort, null);
        }

        private async void Connect(string ipPort, string serverSignatureXmlString = null)
        {
            if (Connected) return;
            try
            {
                string[] split = ipPort.Split(':');
                string ip = split[0];
                int port = int.Parse(split[1]);

                Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(IPAddress.Parse(ip), port);
                connection = new Connection(socket);

                byte[] initialMsg = connection.ReceiveOnceAsync(false);



                //Receive Ok
                Connected = true;
                ClientConnected(this, new ClientConnectedEventArgs(connection));
                connection.DataReceived += (s, e) => { MessageReceived(this, new MessageReceivedEventArgs(s as Connection, e.Data)); };
                connection.BeginReceiving();
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