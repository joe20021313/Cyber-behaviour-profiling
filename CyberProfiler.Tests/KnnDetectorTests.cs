using System.Collections.Generic;
using System.Linq;
using Cyber_behaviour_profiling;

public class KnnDetectorTests
{
    private static ProcessBaseline ValidBaseline() => new ProcessBaseline
    {
        Source = "user",
        Snapshots = Enumerable.Range(0, 20)
            .Select(i => new[] { i % 2 == 0 ? 0.0 : 1.0, 0.0, 0.0, 0.0 })
            .ToArray()
    };

    [Fact]
    public void LoadBaselines_KnownProcess_BaselineIsRetrieved()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>
        {
            ["myapp"] = ValidBaseline()
        });

        try
        {
            var baseline = AnomalyDetector.GetBaseline("myapp.exe");
            Assert.NotNull(baseline);
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void LoadBaselines_UnknownProcess_ReturnsNull()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>
        {
            ["myapp"] = ValidBaseline()
        });

        try
        {
            var baseline = AnomalyDetector.GetBaseline("otherapp.exe");
            Assert.Null(baseline);
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void LoadBaselines_TooFewSnapshots_BaselineIsRejected()
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
            var baseline = AnomalyDetector.GetBaseline("tinyapp.exe");
            Assert.Null(baseline);
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void Evaluate_NoBaseline_SelfReferencingPathUsed()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());

        var profile = ProfileFactory.Empty("unknownapp.exe", 2_120_000_001);
        for (int i = 0; i < 20; i++)
            profile.AnomalyHistory.Add(new[] { 1.0, 0.0, 0.0, 0.0 });

        var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

        Assert.False(result.BaselineUsed);
    }

    [Fact]
    public void Evaluate_WithBaseline_BaselinePathUsed()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>
        {
            ["knownapp"] = ValidBaseline()
        });

        try
        {
            var profile = ProfileFactory.Empty("knownapp.exe", 2_120_000_002);
            for (int i = 0; i < 10; i++)
                profile.AnomalyHistory.Add(new[] { 1.0, 0.0, 0.0, 0.0 });

            var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

            Assert.True(result.BaselineUsed);
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void LoadBaselines_NullBaseline_DoesNotThrow()
    {
        AnomalyDetector.LoadBaselines(null!);
        var baseline = AnomalyDetector.GetBaseline("anything.exe");
        Assert.Null(baseline);
    }
}
