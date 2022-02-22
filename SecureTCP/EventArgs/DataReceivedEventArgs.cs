using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTCP
{
    internal class DataReceivedEventArgs
    {
        public byte[] Data { get; private set; }

        public DataReceivedEventArgs(byte[] data)
        {
            Data = data;
        }
    }
}