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

        private Crypto crypto;

        internal event EventHandler<DataReceivedEventArgs> DataReceived;

        private EncryptionSettings encryptionSettings;

        public Connection(Socket socket, EncryptionSettings encryptionSettings = null)
        {
            this.socket = socket;
            IPEndPoint remoteIpEndPoint = socket.RemoteEndPoint as IPEndPoint;
            RemoteIpPort = remoteIpEndPoint.Address.ToString() + ":" + remoteIpEndPoint.Port;

            IPEndPoint localIpEndPoint = socket.LocalEndPoint as IPEndPoint;
            RemoteIpPort = localIpEndPoint.Address.ToString() + ":" + localIpEndPoint.Port;

            this.encryptionSettings = encryptionSettings;
        }

        public byte[] ReceiveOnceAsync(bool decrypt = true)
        {
            return ReceiveMessage(decrypt).Result;
        }

        public void BeginReceiving()
        {
            if (Receiving) return;

            while (socket.Connected)
            {
                try
                {
                    byte[] message = ReceiveMessage().Result;

                    DataReceived(this, new DataReceivedEventArgs(ReceiveMessage().Result));
                }
                catch (Exception) { throw; }
            }
        }

        private async Task<byte[]> ReceiveMessage(bool decrypt = true)
        {
            byte[] lengthBuffer = new byte[4];
            await socket.ReceiveAsync(lengthBuffer, SocketFlags.None);

            int length = BitConverter.ToInt32(lengthBuffer);
            byte[] buffer = new byte[length];
            await socket.ReceiveAsync(buffer, SocketFlags.None);

            return buffer;
        }

        public async void Send(byte[] message, bool encrypt = true)
        {
            try
            {
                byte[] lengthBytes = BitConverter.GetBytes(message.Length);
                byte[] wrapped = new byte[4 + message.Length];

                Array.Copy(lengthBytes, 0, wrapped, 0, lengthBytes.Length);
                Array.Copy(message, 0, wrapped, 4, message.Length);

                await socket.SendAsync(wrapped, SocketFlags.None);
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