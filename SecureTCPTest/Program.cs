using SecureTCP;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Net;

ECDiffieHellman bob = ECDiffieHellman.Create(ECCurve.NamedCurves.brainpoolP512r1);
ECDiffieHellman alice = ECDiffieHellman.Create(ECCurve.NamedCurves.brainpoolP512r1);

ECDiffieHellman alicePub = ECDiffieHellman.Create(alice.ExportParameters(false));
ECDiffieHellman bobPub = ECDiffieHellman.Create(bob.ExportParameters(false));

byte[] sharedSecred1 = alice.DeriveKeyMaterial(bobPub.PublicKey);
byte[] sharedSecred2 = bob.DeriveKeyMaterial(alicePub.PublicKey);
bool equal = sharedSecred1 == sharedSecred2;

ECDsa bobSigner = ECDsa.Create(bob.ExportParameters(true));
ECDsa bobVerifier = ECDsa.Create(alicePub.ExportParameters(false));

ECDsa aliceSigner = ECDsa.Create(alice.ExportParameters(true));
ECDsa aliceVerifier = ECDsa.Create(bobPub.ExportParameters(false));

byte[] hash = SHA512.HashData(Convert.FromBase64String("testtesttest"));
byte[] bobSig = bobSigner.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

bool veri = aliceVerifier.VerifyHash(hash, bobSig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);



ECDsa ecd = ECDsa.Create(ECCurve.NamedCurves.brainpoolP512r1);
var p = ecd.ExportParameters(true);


ECDsa verifier = ECDsa.Create();
ECParameters ecParams = new ECParameters();
ecParams.Q.X = p.Q.X;
ecParams.Q.Y = p.Q.Y;
ecParams.Curve = ECCurve.NamedCurves.brainpoolP512r1;
verifier.ImportParameters(ecParams);

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