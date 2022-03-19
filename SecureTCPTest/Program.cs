using SecureTCP;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Net;
using System.Diagnostics;


//Test objects:
SecureTcpServer server;
SecureTcpClient client;
int serverReceived = 0;
int clientReceived = 0;
const int tests = 7;
int testsDone = 0;
RunTests();

Console.ReadLine();
async void RunTests()
{
    //Test handshake
    server = new SecureTcpServer("127.0.0.1", 23444);
    server.Start();
    client = new SecureTcpClient();
    await client.Connect("127.0.0.1", 23444);
    Wait();
    AssertTrue(client.Connected);
    AssertFalse(client.Certified);
    AssertEquals(server.Clients.Count(), 1);
    TestDone();

    //Disconnect all
    server.DisconnectAll();
    Wait();
    AssertEquals(client.Connected, false);
    AssertEquals(server.Clients.Count(), 0);
    TestDone();

    //Connect with certificate
    server.GenerateCertificate();
    Wait();
    string conString = server.ExportConnectionString();
    AssertTrue(conString.Length > 10);
    await client.Connect(conString);
    Wait();
    AssertTrue(client.Certified);
    AssertTrue(client.Connected);
    try
    {
        await client.Connect(conString);
        AssertTrue(false);
    } catch { }
    TestDone();

    //Client disconnect
    client.Disconnect();
    Wait();
    AssertFalse(client.Connected);
    AssertEquals(server.Clients.Count(), 0);
    TestDone();

    //Messages
    await client.Connect(server.Ip, server.Port);
    AssertFalse(client.Certified);
    client.MessageReceived += ClientMsgReceive;
    server.MessageReceived += ServerMsgReceive;
    client.Send(new byte[23]);
    server.BroadCast(new byte[23]);
    Wait();
    AssertEquals(23, clientReceived);
    AssertEquals(23, serverReceived);
    TestDone();

    //Multiple clients
    SecureTcpClient secureClient = new SecureTcpClient();
    await secureClient.Connect(conString);
    Wait();
    AssertTrue(secureClient.Connected);
    AssertTrue(secureClient.Certified);
    AssertEquals(server.Clients.Count(), 2);
    clientReceived = 0;
    secureClient.MessageReceived += ClientMsgReceive;
    server.BroadCast(new byte[12]);
    Wait();
    AssertEquals(clientReceived, 24);
    TestDone();

    //Server stop
    server.Stop();
    Wait();
    AssertFalse(client.Connected);
    AssertFalse(secureClient.Connected);
    AssertFalse(server.Running);
    server.Start();
    await secureClient.Connect(conString);
    await client.Connect(server.Ip, server.Port);
    Wait();
    AssertEquals(server.Clients[0], secureClient.LocalIpPort);
    AssertEquals(server.Clients[1], client.LocalIpPort);
    AssertTrue(server.Running);

    TestDone();

    Console.WriteLine("All tests passed!");
}

void TestDone()
{
    testsDone++;
    Console.WriteLine("Test " + testsDone + "/" + tests + " done");
}

void ServerMsgReceive(object sender, MessageReceivedEventArgs e)
{
    serverReceived += e.Data.Length;
}

void ClientMsgReceive(object sender, MessageReceivedEventArgs e)
{
    clientReceived += e.Data.Length;
}




void Wait(int mult250 = 1)
{
    for (int i = 0; i < mult250; i++)
    {
        Thread.Sleep(75);
    }
}

void AssertEquals(object input1, object input2)
{
    if (!input1.Equals(input2)) throw new Exception("Assertion failed; Not equal");
}

void AssertTrue(bool input)
{
    if (!input) throw new Exception("Assertion failed; Not true");
}

void AssertFalse(bool input)
{
    if (input) throw new Exception("Assertion failed; Not false");
}