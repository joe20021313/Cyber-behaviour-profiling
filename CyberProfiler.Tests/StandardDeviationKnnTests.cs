using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using Cyber_behaviour_profiling;

public class StandardDeviationKnnTests
{
    private static string ProjectRoot =>
        Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "../../../../"));

    private static double[][] LoadSnapshots(string fileName)
    {
        var path = Path.Combine(ProjectRoot, fileName);
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement
            .GetProperty("Baselines")
            .GetProperty("testapp")
            .GetProperty("Snapshots")
            .Deserialize<double[][]>()!;
    }

    private static ProcessBaseline BuildSafeBaseline()
    {
        var snapshots = LoadSnapshots("safebaseline.json");
        return new ProcessBaseline { Source = "user", Snapshots = snapshots, };
    }

    private static double[][] NormalCandidateSnapshots =>
        LoadSnapshots("safebaseline.json").TakeLast(5).ToArray();


    private static double[][] MaliciousCandidateSnapshots =>
        LoadSnapshots("maliciousbaseline.json")
            .Where(s => s[0] > 10.0)
            .ToArray();

    [Fact]
    public void RealBaseline_NormalActivity_IsNotFlagged()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>
        {
            ["testapp"] = BuildSafeBaseline()
        });

        try
        {
            var profile = ProfileFactory.Empty("testapp.exe", 2_140_000_001); // creates a new profile with no history
            foreach (var snap in NormalCandidateSnapshots)
                profile.AnomalyHistory.Add(snap);

            var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

            double avgCandidate = NormalCandidateSnapshots.Average(s => s[0]);
            Console.WriteLine(
                $"[NORMAL] Avg: {avgCandidate:F4} | KNN: {result.KnnDistance:F4} | Threshold: {result.Threshold:F4} | Diff: {result.KnnDistance - result.Threshold:F4} | Anomaly: {result.AnomalyDetected}");

            Assert.True(result.BaselineUsed,
                "Baseline was not loaded");
            Assert.False(result.AnomalyDetected,
                $"Normal activity was incorrectly flagged. Dist={result.KnnDistance:F4}, Threshold={result.Threshold:F4}");
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void RealBaseline_MaliciousSpike_IsDetected()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>
        {
            ["testapp"] = BuildSafeBaseline()
        });

        try
        {
            var profile = ProfileFactory.Empty("testapp.exe", 2_140_000_002); // creates a new profile with no history
            foreach (var snap in MaliciousCandidateSnapshots)
                profile.AnomalyHistory.Add(snap);

            var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

            double avgCandidate = MaliciousCandidateSnapshots.Average(s => s[0]);
            Console.WriteLine(
                $"[MALICIOUS] Avg: {avgCandidate:F4} | KNN: {result.KnnDistance:F4} | Threshold: {result.Threshold:F4} | Diff: {result.KnnDistance - result.Threshold:F4} | Anomaly: {result.AnomalyDetected}");

            Assert.True(result.BaselineUsed,
                "Baseline was not loaded");
            Assert.True(result.AnomalyDetected,
                $"Malicious spike was not detected. Dist={result.KnnDistance:F4}, Threshold={result.Threshold:F4}");
            Assert.True(result.KnnDistance > result.Threshold,
                $"KNN distance {result.KnnDistance:F4} did not exceed threshold {result.Threshold:F4}");
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }
}
