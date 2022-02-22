using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.Net;

namespace SecureTCP
{
    public class Connection
    {
        private Socket socket;
        public string RemoteIpPort { get; private set; }
        public string LocalIpPort { get; private set; }
        public bool Receiving = false;

        RSA signer;
        RSA verifier;
        Aes encrypter;

        internal event EventHandler<DataReceivedEventArgs> DataReceived;

        public Connection(Socket socket)
        {
            this.socket = socket;
            IPEndPoint remoteIpEndPoint = socket.RemoteEndPoint as IPEndPoint;
            RemoteIpPort = remoteIpEndPoint.Address.ToString() + ":" + remoteIpEndPoint.Port;

            IPEndPoint localIpEndPoint = socket.LocalEndPoint as IPEndPoint;
            RemoteIpPort = localIpEndPoint.Address.ToString() + ":" + localIpEndPoint.Port;
        }

        public async Task<byte[]> ReceiveOnce()
        {

        }

        public async Task<byte[]> Receive(int byteCount)
        {
            
            return bytes;
        }

        public async void BeginReceive()
        {
            if (Receiving) return;

            while (socket.Connected)
            {
                DataReceived(this, new DataReceivedEventArgs(ReceiveMessage().Result));
            }
        }

        public async Task<byte[]> ReceiveMessage()
        {
            byte[] lengthBuffer = new byte[4];
            await socket.ReceiveAsync(lengthBuffer, SocketFlags.None);

            int length = BitConverter.ToInt32(lengthBuffer, 0);
            byte[] buffer = new byte[length];
            await socket.ReceiveAsync(buffer, SocketFlags.None);

            return buffer;
        }

        public async void Send(byte[] data, bool wrap = true)
        {
            try
            {
                byte[] message = wrap ? NetworkMessage.Wrap(data) : data;
                await socket.SendAsync(message, SocketFlags.None);
            }
            catch (Exception)
            {
                throw new Exception("Send failed");
            }
        }

        public void ShutDown()
        {
            socket.Shutdown(SocketShutdown.Send);
        }
    }
}