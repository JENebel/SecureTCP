using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    public class ClientConnectedEventArgs
    {
        public Connection Connection { get; private set; }

        public ClientConnectedEventArgs(Connection connection)
        {
            Connection = connection;
        }
    }
}