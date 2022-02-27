using SecureTCP;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using System.Runtime.InteropServices;

var k = ECDsa.Create(ECCurve.NamedCurves.nistP521);
var param = k.ExportParameters(true);



SecureTcpServer server = new SecureTcpServer("127.0.0.1", 13222);
server.Start();

SecureTcpClient client = new SecureTcpClient();
client.Connect("127.0.0.1:13222");

Console.ReadLine();