using SecureTCP;

SecureTcpServer server = new SecureTcpServer("127.0.0.1", 12888);
server.Start();

SecureTcpClient client = new SecureTcpClient();

client.Connect("127.0.0.1:12888");

Console.ReadLine();