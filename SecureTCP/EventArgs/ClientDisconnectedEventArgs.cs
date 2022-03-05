using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public enum DisconnectReason { Expected, Unexpected}

    public class ClientDisconnectedEventArgs
    {
        public string IpPort { get; private set; }
        public string Reason { get; private set; }
        public DisconnectReason DisconnectReason { get; private set; }

        public ClientDisconnectedEventArgs(string ipPort, DisconnectReason disconnectReason, string reason)
        {
            IpPort = ipPort;
            Reason = reason;
            DisconnectReason = disconnectReason;
        }
    }
}
