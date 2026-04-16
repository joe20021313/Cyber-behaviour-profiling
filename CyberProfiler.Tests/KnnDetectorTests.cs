using System;
using System.Collections.Generic;
using System.Linq;
using Cyber_behaviour_profiling;

public class KnnDetectorTests
{
    private static ProcessBaseline BuildBimodalBaseline()
    {
        var snapshots = new List<double[]>();

        for (int i = 0; i < 10; i++)
            snapshots.Add(new[] { 1.0 + i * 0.01, 0.0, 0.0, 0.0 });

        snapshots.Add(new[] { 4.0, 0.0, 0.0, 0.0 });
        snapshots.Add(new[] { 7.0, 2.0, 0.0, 1.0 });
        snapshots.Add(new[] { 11.0, 0.0, 1.0, 3.0 });
        snapshots.Add(new[] { 6.0, 2.0, 0.0, 1.0 });
        snapshots.Add(new[] { 14.0, 3.0, 0.0, 1.0 });
        snapshots.Add(new[] { 5.0, 0.0, 1.0, 1.0 });
        snapshots.Add(new[] { 13.0, 1.0, 1.0, 1.0 });
        snapshots.Add(new[] { 8.0, 2.0, 1.0, 0.0 });
        snapshots.Add(new[] { 21.0, 6.0, 1.0, 5.0 });
        snapshots.Add(new[] { 20.0, 5.0, 0.0, 3.0 });

        return new ProcessBaseline
        {
            Source = "user",
            Snapshots = snapshots.ToArray()
        };
    }

    private static ProcessProfile BuildProfile(string name, int pid, params double[][] snapshots)
    {
        var profile = ProfileFactory.Empty(name, pid);
        foreach (double[] snapshot in snapshots)
            profile.AnomalyHistory.Add(snapshot);
        return profile;
    }

    [Fact]
    public void NoBaseline_BimodalHistory_AnomalyDetected()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());

        var profile = ProfileFactory.Empty("nobaseline.exe", 2_120_000_001);
        for (int i = 0; i < 15; i++)
            profile.AnomalyHistory.Add(new[] { 0.5, 0.0, 0.0, 0.0 });
        for (int i = 0; i < 15; i++)
            profile.AnomalyHistory.Add(new[] { 8.0, 1.0, 1.0, 1.0 });

        var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

        Assert.True(result.AnomalyDetected);
        Assert.False(result.BaselineUsed);
    }

    [Fact]
    public void BimodalBaseline_ActiveClusterCandidate_NoAnomaly()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>
        {
            ["knntest"] = BuildBimodalBaseline()
        });

        try
        {
            var profile = BuildProfile(
                "knntest.exe",
                2_120_000_002,
                new[] { 18.0, 6.0, 0.0, 3.0 },
                new[] { 16.0, 5.0, 0.0, 2.0 },
                new[] { 19.0, 6.0, 1.0, 3.0 },
                new[] { 17.0, 5.0, 0.0, 2.0 },
                new[] { 20.0, 6.0, 1.0, 3.0 });

            var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

            Assert.True(result.BaselineUsed);
            Assert.False(result.AnomalyDetected,
                $"Unexpected anomaly. Tripwire={result.TripwireFired}, Score={result.Score}, Dist={result.KnnDistance:F3}, Th={result.Threshold:F3}, Metrics={string.Join(" | ", result.SpikedMetrics)}");
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void BimodalBaseline_OutOfDistributionSpike_AnomalyDetected()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>
        {
            ["knntest"] = BuildBimodalBaseline()
        });

        try
        {
            var profile = BuildProfile(
                "knntest.exe",
                2_120_000_003,
                new[] { 80.0, 20.0, 5.0, 15.0 },
                new[] { 75.0, 18.0, 4.0, 14.0 },
                new[] { 82.0, 22.0, 5.0, 16.0 },
                new[] { 78.0, 19.0, 5.0, 15.0 },
                new[] { 80.0, 20.0, 5.0, 15.0 });

            var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

            Assert.True(result.BaselineUsed);
            Assert.True(result.AnomalyDetected);
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void BaselineWithTooFewSnapshots_IsIgnored()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>
        {
            ["tinyapp"] = new ProcessBaseline
            {
                Source = "user",
                Snapshots = Enumerable.Range(0, 3)
                    .Select(_ => new[] { 1.0, 0.0, 0.0, 0.0 })
                    .ToArray()
            }
        });

        try
        {
            Assert.Null(AnomalyDetector.GetBaseline("tinyapp.exe"));
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void EarlierSpikeThenQuietLatest_StillDetectsAnomaly()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());

        var profile = ProfileFactory.Empty("writer.exe", 2_120_000_004);
        for (int i = 0; i < 8; i++)
            profile.AnomalyHistory.Add(new[] { 1.0, 0.0, 0.0, 0.0 });

        profile.AnomalyHistory.Add(new[] { 18.0, 5.0, 3.0, 2.0 });
        profile.AnomalyHistory.Add(new[] { 1.0, 0.0, 0.0, 0.0 });

        var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

        Assert.True(result.AnomalyDetected);
    }

    [Fact]
    public void NoBaseline_ShortSensitiveBurst_TripwireDetectsAnomaly()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());

        var profile = ProfileFactory.Empty("lazagne.exe", 2_120_000_005);
        profile.AnomalyHistory.Add(new[] { 0.0, 0.0, 0.0, 9.0 });
        profile.AnomalyHistory.Add(new[] { 0.0, 0.0, 0.0, 0.0 });
        profile.AnomalyHistory.Add(new[] { 0.0, 0.0, 0.0, 0.0 });

        var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

        Assert.True(result.AnomalyDetected);
        Assert.False(result.BaselineUsed);
        Assert.True(result.TripwireFired);
        Assert.Contains("tripwire", result.TripwireReason, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(result.SpikedMetrics, m =>
            m.Contains("Sensitive Access Rate", StringComparison.OrdinalIgnoreCase));
    }
}