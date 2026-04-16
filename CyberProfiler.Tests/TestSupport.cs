using System;
using System.IO;
using Cyber_behaviour_profiling;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

internal static class ProfileFactory
{
    public static ProcessProfile Empty(string name = "testprocess.exe", int pid = 2_000_000_000) =>
        new() { ProcessId = pid, ProcessName = name, FirstSeen = DateTime.Now };

    public static SuspiciousEvent Event(
        string eventType,
        string indicator,
        string rawData,
        string category,
        DateTime? timestamp = null,
        DateTime? lastSeen = null,
        int attemptCount = 1) =>
        new()
        {
            Timestamp = timestamp ?? DateTime.Now,
            LastSeen = lastSeen ?? timestamp ?? DateTime.Now,
            EventType = eventType,
            MatchedIndicator = indicator,
            RawData = rawData,
            Category = category,
            AttemptCount = attemptCount
        };

    public static ProcessProfile WithEvent(
        string eventType,
        string indicator,
        string rawData,
        string category,
        string name = "testprocess.exe",
        int pid = 2_000_000_000)
    {
        var profile = Empty(name, pid);
        AddEvent(profile, eventType, indicator, rawData, category);
        return profile;
    }

    public static void AddEvent(
        ProcessProfile profile,
        string eventType,
        string indicator,
        string rawData,
        string category,
        DateTime? timestamp = null,
        DateTime? lastSeen = null,
        int attemptCount = 1)
    {
        profile.EventTimeline.Add(Event(
            eventType,
            indicator,
            rawData,
            category,
            timestamp,
            lastSeen,
            attemptCount));
    }
}

internal static class TestDataLoader
{
    private static readonly object Gate = new();

    public static void EnsureLoaded()
    {
        lock (Gate)
        {
            string dataPath = Path.GetFullPath(
                Path.Combine(AppContext.BaseDirectory, "../../../../data.json"));
            MapToData.LoadData(dataPath);
        }
    }
}

internal static class TestScope
{
    public static void WithFreshSession(Action action, bool loadData = false)
    {
        MapToData.ResetSession();
        try
        {
            if (loadData)
                TestDataLoader.EnsureLoaded();

            action();
        }
        finally
        {
            MapToData.ResetSession();
        }
    }
}