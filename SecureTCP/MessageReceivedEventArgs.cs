using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public class MessageReceivedEventArgs : EventArgs
    {
        public Connection Connection { get; private set; }
        public byte[] Data { get; private set; }

        public MessageReceivedEventArgs(Connection connection, byte[] data)
        {
            Connection = connection;
            Data = data;
        }
    }
}
