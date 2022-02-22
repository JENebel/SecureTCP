using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public enum DisconnectReason { BadSecurity, Closed, Error }

    public class ClientDisconnectedEventArgs
    {
        public Connection Connection { get; private set; }
        public DisconnectReason DisconnectReason { get; private set; }

        public ClientDisconnectedEventArgs(Connection connection, DisconnectReason reason)
        {
            Connection = connection;
            DisconnectReason = reason;
        }
    }
}
