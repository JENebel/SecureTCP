using SecureTCP;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Net;

ECDsa ecd = ECDsa.Create(ECCurve.NamedCurves.brainpoolP512r1);

var pbep = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 11111);
SecureTcpServer server = new SecureTcpServer("127.0.0.1", 13222, Convert.FromBase64String(Convert.ToBase64String(ecd.ExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes("password"), pbep))), "password");
var en = new EncryptionSettings(EncryptionSettings.AesType.AES_128, EncryptionSettings.CurveType.Nist521);

server.Start(en);

SecureTcpClient client = new SecureTcpClient();
client.ClientConnected += Con;
client.Connect(server.ExportConnectionString());

server.MessageReceived += Received;
client.MessageReceived += Received;

while (true)
{
    Console.ReadLine();
}

void Con(object sender, ClientConnectedEventArgs e)
{
    client.Send(Encoding.UTF8.GetBytes("Hej"));
    server.BroadCast(Encoding.UTF8.GetBytes("Succes"));
}

void Received(object sender, MessageReceivedEventArgs e)
{
    Console.WriteLine(Encoding.UTF8.GetString(e.Data));
}