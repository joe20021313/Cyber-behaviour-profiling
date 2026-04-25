using System;
using System.Collections.Generic;
using System.IO;
using Cyber_behaviour_profiling;

public class MonitoringLimitTests
{
    [Fact]
    public void MaxMonitoredProcesses_IsDefinedAsFour()
    {
        Assert.Equal(4, LiveMonitoringSession.MaxMonitoredProcesses);
    }

    [Fact]
    public void Start_WithFiveProcesses_ThrowsArgumentException()
    {
        var session = new LiveMonitoringSession();
        var processes = new List<string> { "a.exe", "b.exe", "c.exe", "d.exe", "e.exe" };

        var ex = Assert.Throws<ArgumentException>(() =>
            session.Start(processes, "data.json"));

        Assert.Contains("4", ex.Message);
    }

    [Fact]
    public void Start_WithFourProcesses_DoesNotThrowLimitException()
    {
        var session = new LiveMonitoringSession();
        var processes = new List<string> { "a.exe", "b.exe", "c.exe", "d.exe" };

        // Should throw FileNotFoundException (data.json missing in test env),
        // not ArgumentException — meaning the process limit check passed
        Assert.Throws<FileNotFoundException>(() =>
            session.Start(processes, "data.json"));
    }
}
