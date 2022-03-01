using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public enum DisconnectReason { Normal, Disconnected, SecurityError, ServerClosed}

    public class ClientDisconnectedEventArgs
    {
        public string IpPort { get; private set; }
        public DisconnectReason DisconnectReason { get; private set; }

        public ClientDisconnectedEventArgs(string ipPort, DisconnectReason reason)
        {
            IpPort = ipPort;
            DisconnectReason = reason;
        }
    }
}
