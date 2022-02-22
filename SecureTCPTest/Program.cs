using SecureTCP;


SecureTcpServer server = new SecureTcpServer("127.0.0.1", 13888);

server.Start();

server.Stop();



Console.ReadLine();