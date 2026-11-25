// A test server that keeps running, so it can be poked with ldapsearch, an LDAP browser or a service in a container:
//   dotnet run --project samples/DotLdap.Sample.Standalone -- [--port 10389] [--ldaps-port 10636] [--ad] [--ldif data.ldif]
using System.Diagnostics;
using DotLdap.Sample.Standalone;

var watch = Stopwatch.StartNew();
using var server = StandaloneServer.Start(StandaloneSettings.Parse(args));
Console.WriteLine($"Started in {watch.ElapsedMilliseconds} ms.");
File.WriteAllText("dotldap-ca.pem", server.CertificatePem);
foreach (var line in StandaloneServer.Instructions(server)) Console.WriteLine(line);

using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stop.Cancel();
};

var seen = 0;
try
{
    while (true)
    {
        await Task.Delay(200, stop.Token);
        var requests = server.Requests;
        for (; seen < requests.Count; seen++) Console.WriteLine(requests[seen]);
    }
}
catch (OperationCanceledException)
{
    Console.WriteLine("Stopped.");
}
