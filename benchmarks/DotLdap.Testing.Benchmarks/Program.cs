using BenchmarkDotNet.Running;
using DotLdap.Testing.Benchmarks;

if (args is ["startup", ..])
{
    await StartupComparison.RunAsync(args[1..]);
}
else
{
    BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
}
