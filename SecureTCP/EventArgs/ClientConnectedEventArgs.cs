using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public class ClientConnectedEventArgs
    {
        public string IpPort { get; private set; }

        public ClientConnectedEventArgs(string ipPort)
        {
            IpPort = ipPort;
        }
    }
}