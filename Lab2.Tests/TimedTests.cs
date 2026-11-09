using System.Diagnostics;
using NUnit.Framework;

namespace Lab2.Tests;

public abstract class TimedTests
{
    private Stopwatch stopwatch = new();

    [SetUp]
    public void StartTiming()
    {
        stopwatch.Restart();
    }

    [TearDown]
    public void ReportTiming()
    {
        stopwatch.Stop();
        TestContext.Progress.WriteLine($"{TestContext.CurrentContext.Test.Name}: {stopwatch.Elapsed.TotalMilliseconds:F3} мс");
    }
}
