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
    public enum MessageType { Normal, Handshake, Shutdown, HandshakeError }

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
            byte[] metaBuffer = new byte[5];
            MessageType type = ByteToMsgType(metaBuffer[4]);
//Add code for Shutdown and HandshakeError

            await socket.ReceiveAsync(metaBuffer, SocketFlags.None);

            int length = BitConverter.ToInt32(metaBuffer);
            byte[] buffer = new byte[length];
            byte[] vs = new byte[length + 2];
            socket.ReceiveBufferSize = length;
            await socket.ReceiveAsync(buffer, SocketFlags.None);

            return type == MessageType.Normal ? crypto.Decrypt(buffer) : buffer;
        }

        public async void Send(byte[] message, MessageType type, bool encrypt = true)
        {
            try
            {
                byte[] lengthBytes = BitConverter.GetBytes(message.Length);
                byte[] wrapped = new byte[5 + message.Length];
                message[4] = MsgTypeToByte(type);

                Array.Copy(lengthBytes, 0, wrapped, 1, lengthBytes.Length);
                Array.Copy(message, 0, wrapped, 5, message.Length);

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

        byte MsgTypeToByte(MessageType type)
        {
            switch (type)
            {
                case MessageType.Normal:
                    return 0;
                case MessageType.Handshake:
                    return 1;
                case MessageType.Shutdown:
                    return 2;
                case MessageType.HandshakeError:
                    return 3;
                default:
                    throw new Exception("No byte value corresponding to " + type.ToString());
            }
        }

        MessageType ByteToMsgType(byte msgByte)
        {
            switch (msgByte)
            {
                case 0:
                    return MessageType.Normal;
                case 1:
                    return MessageType.Handshake;
                case 2:
                    return MessageType.Shutdown;
                case 3:
                    return MessageType.HandshakeError;
                default:
                    throw new Exception("No message type corresponding to " + msgByte);
            }
        }
    }
}