using SecureTCP;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Net;
using System.Diagnostics;


SecureTcpServer server = new SecureTcpServer("127.0.0.1", 45111);


SecureTcpClient client = new SecureTcpClient();

client.ClientConnected += ClientConnected;
server.ClientConnected += ServerConnected;
server.ClientDisconnected += ServerDisconnected;



server.Start();
client.Connect("127.0.0.1", 45111);

Console.ReadLine();


void ServerConnected(object sender, ClientConnectedEventArgs e)
{
    Console.WriteLine("Incoming from: " + e.IpPort);
}

void ClientConnected(object sender, ClientConnectedEventArgs e)
{
    var asr = server.Clients;
    server.Send(Encoding.UTF8.GetBytes("Johnny"), asr[0]);
    Thread.Sleep(1000);
    client.Disconnect();
}

void ServerDisconnected(object sender, ClientDisconnectedEventArgs e)
{
    Console.WriteLine("Disconnected: " + e.IpPort);

    var asr = server.Clients;
}