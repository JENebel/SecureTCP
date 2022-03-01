using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public class MessageReceivedEventArgs : EventArgs
    {
        public string IpPort { get; private set; }
        public byte[] Data { get; private set; }

        public MessageReceivedEventArgs(string ipPort, byte[] data)
        {
            IpPort = ipPort;
            Data = data;
        }
    }
}
