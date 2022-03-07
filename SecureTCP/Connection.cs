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
    internal enum MessageType { Normal, Handshake, Shutdown, SecurityError, None }

    internal class Connection
    {
        private Socket socket;
        public string RemoteIpPort { get; private set; }
        public string LocalIpPort { get; private set; }
        public bool Receiving = false;

        public Crypto Crypto { private get; set; }

        internal event EventHandler<DataReceivedEventArgs> DataReceived;
        internal event EventHandler<ClientDisconnectedEventArgs> Disconnected;

        public Connection(Socket socket)
        {
            this.socket = socket;
            IPEndPoint remoteIpEndPoint = socket.RemoteEndPoint as IPEndPoint;
            RemoteIpPort = remoteIpEndPoint.Address.ToString().TrimStart(new char[] {':', 'f'}) + ":" + remoteIpEndPoint.Port;

            IPEndPoint localIpEndPoint = socket.LocalEndPoint as IPEndPoint;
            LocalIpPort = localIpEndPoint.Address.ToString().TrimStart(new char[] { ':', 'f' }) + ":" + localIpEndPoint.Port;
        }

        public byte[] ReceiveOnceAsync()
        {
            return ReceiveMessage().Result;
        }

        public async void BeginReceiving()
        {
            if (Receiving) return;
            Receiving = true;

            while (socket.Connected)
            {
                try
                {
                    byte[] message = await ReceiveMessage();

                    DataReceived(this, new DataReceivedEventArgs(message));
                }
                catch (AggregateException e)
                {
                    var ex = e.GetBaseException();
                    if (ex.GetType() == typeof(SocketException))
                    {
                        SocketException se = ex as SocketException;
                        if (se.SocketErrorCode == SocketError.ConnectionReset)
                        {
                            ConnectionLost();
                        }
                    }
                }
                catch (BadSignatureException) 
                {
                    ShutDown("Bad Signature");
                }
                catch { ConnectionLost(); }
            }
        }

        private async Task<byte[]> ReceiveMessage()
        {
            byte[] metaBuffer = new byte[3];
            byte[] buffer = new byte[0];
            MessageType type = MessageType.None;
            while (!(type == MessageType.Normal || type == MessageType.Handshake))
            {
                await socket.ReceiveAsync(metaBuffer, SocketFlags.None);

                type = ByteToMsgType(metaBuffer[2]);

                int length = BitConverter.ToUInt16(metaBuffer);

                if (length > 0)
                {
                    buffer = new byte[length];
                    await socket.ReceiveAsync(buffer, SocketFlags.None);
                }

                if (type != MessageType.Normal && type != MessageType.Handshake)
                    HandleSystemMessage(buffer, type);
            }
            
            return type == MessageType.Normal? Crypto.Decrypt(buffer) : buffer;
        }

        private void HandleSystemMessage(byte[] data, MessageType type)
        {
            switch (type)
            {
                case MessageType.Normal:
                    throw new ArgumentException("Normal mesage not expected to end up here");
                case MessageType.Handshake:
                    throw new ArgumentException("Handshake mesage not expected to end up here");
                case MessageType.Shutdown:
                    ShutDown("Terminated by server");
                    break;
                case MessageType.SecurityError:
                    ShutDown("Remote security error");
                    break;
                case MessageType.None:
                    throw new ArgumentException("Handshake mesage not expected to end up here");
                default:
                    throw new ArgumentException("Unknown Message Type");
            }
        }

        public async void Send(byte[] message, MessageType type)
        {
            try
            {
                byte[] processedMessage = type == MessageType.Normal ? Crypto.Encrypt(message) : message;
                byte[] lengthBytes = BitConverter.GetBytes((ushort)processedMessage.Length);
                byte[] wrapped = new byte[3 + processedMessage.Length];
                wrapped[2] = MsgTypeToByte(type);

                Array.Copy(lengthBytes, 0, wrapped, 0, lengthBytes.Length);
                Array.Copy(processedMessage, 0, wrapped, 3, processedMessage.Length);

                await socket.SendAsync(wrapped, SocketFlags.None);
            }
            catch (Exception)
            {
                ConnectionLost();
            }
        }

        public void ShutDown()
        {
            ShutDown("Expected shutdown");
        }

        private void ShutDown(string reason)
        {
            try
            {
                Send(new byte[0], MessageType.Shutdown);
                socket.Shutdown(SocketShutdown.Both);
            }
            catch (Exception) { }
            
            Disconnected(this, new ClientDisconnectedEventArgs(RemoteIpPort, DisconnectReason.Expected, reason));
        }

        private void ConnectionLost()
        {
            socket.Shutdown(SocketShutdown.Send);
            try
            {
                socket.Shutdown(SocketShutdown.Receive);
            }
            catch { }

            Disconnected(this, new ClientDisconnectedEventArgs(RemoteIpPort, DisconnectReason.Unexpected, "Connection lost"));
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
                case MessageType.SecurityError:
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
                    return MessageType.SecurityError;
                default:
                    throw new Exception("No message type corresponding to " + msgByte);
            }
        }
    }
}