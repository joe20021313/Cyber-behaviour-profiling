using System;
using System.Collections.Generic;
using System.Linq;

namespace Cyber_behaviour_profiling
{
    public class AnomalyResult
    {
        public bool AnomalyDetected { get; set; }
        public List<string> SpikedMetrics { get; set; } = new();
        public double KnnDistance { get; set; }
        public double Threshold { get; set; }
        public int Score { get; set; }
    }

    public static class AnomalyDetector
    {
        private const int K = 3;
        private const int MinSamples = 5;
        private const double ZThreshold = 2.0;

        private static readonly string[] MetricNames =
            { "File Write Rate", "File Delete Rate", "Event Rate", "Network Connections" };

        public static AnomalyResult Evaluate(ProcessProfile profile, ProcessContext ctx)
        {
            var result = new AnomalyResult();

            double elapsed = profile.PrevSnapshotTime == DateTime.MinValue
                ? 0
                : (DateTime.Now - profile.PrevSnapshotTime).TotalSeconds;

            if (elapsed < 0.5) return result;

            double writeRate = (profile.TotalFileWrites - profile.PrevFileWrites) / elapsed;
            double deleteRate = (profile.TotalFileDeletes - profile.PrevFileDeletes) / elapsed;
            double eventRate = (profile.EventTimeline.Count - profile.PrevEventCount) / elapsed;
            double netConns = ctx.NetworkConnCount;

            double[] features = { writeRate, deleteRate, eventRate, netConns };

            profile.PrevFileWrites = profile.TotalFileWrites;
            profile.PrevFileDeletes = profile.TotalFileDeletes;
            profile.PrevEventCount = profile.EventTimeline.Count;
            profile.PrevSnapshotTime = DateTime.Now;

            profile.AnomalyHistory.Add(features);

            if (profile.AnomalyHistory.Count < MinSamples)
                return result;

            var normalized = Normalize(profile.AnomalyHistory);
            double[] current = normalized[normalized.Count - 1];

            var distances = new List<double>();
            for (int i = 0; i < normalized.Count - 1; i++)
                distances.Add(EuclideanDistance(current, normalized[i]));

            distances.Sort();
            double knnScore = distances.Take(K).Average();

            profile.KnnScores.Add(knnScore);
            result.KnnDistance = knnScore;

            if (profile.KnnScores.Count < 3)
                return result;

            double mean = profile.KnnScores.Average();
            double std = StandardDeviation(profile.KnnScores, mean);
            double threshold = mean + ZThreshold * std;
            result.Threshold = threshold;

            if (std < 0.1 || knnScore <= threshold)
                return result;

            result.AnomalyDetected = true;

            var history = profile.AnomalyHistory.Take(profile.AnomalyHistory.Count - 1).ToList();
            for (int d = 0; d < features.Length; d++)
            {
                double dimMean = history.Select(f => f[d]).Average();
                double dimStd = StandardDeviation(history.Select(f => f[d]).ToList(), dimMean);
                if (dimStd > 0.01 && (features[d] - dimMean) / dimStd > ZThreshold)
                {
                    string unit = d == 3 ? "" : "/sec";
                    result.SpikedMetrics.Add(
                        $"{MetricNames[d]}: {features[d]:F1}{unit} (baseline: {dimMean:F1}{unit})");
                }
            }

            double severity = (knnScore - threshold) / (threshold > 0.001 ? threshold : 1);
            result.Score = Math.Clamp((int)(severity * 25) + 15, 15, 45);

            return result;
        }

        public static AnomalyResult EvaluateHistory(ProcessProfile profile)
        {
            var result = new AnomalyResult();
            var history = profile.AnomalyHistory;

            if (history.Count < MinSamples)
                return result;

            var normalized = Normalize(history);

            var allScores = new double[normalized.Count];
            for (int i = 0; i < normalized.Count; i++)
            {
                var distances = new List<double>();
                for (int j = 0; j < normalized.Count; j++)
                {
                    if (i == j) continue;
                    distances.Add(EuclideanDistance(normalized[i], normalized[j]));
                }
                distances.Sort();
                allScores[i] = distances.Take(K).Average();
            }

            double mean = allScores.Average();
            double std = StandardDeviation(allScores.ToList(), mean);
            double threshold = mean + ZThreshold * std;

            result.Threshold = threshold;

            int worstIdx = -1;
            double worstScore = 0;
            for (int i = 0; i < allScores.Length; i++)
            {
                if (allScores[i] > worstScore)
                {
                    worstScore = allScores[i];
                    worstIdx = i;
                }
            }

            result.KnnDistance = worstScore;

            if (std < 0.1 || worstScore <= threshold || worstIdx < 0)
                return result;

            result.AnomalyDetected = true;

            double[] worstFeatures = history[worstIdx];
            var baseline = history.Where((_, i) => i != worstIdx).ToList();

            for (int d = 0; d < worstFeatures.Length; d++)
            {
                double dimMean = baseline.Select(f => f[d]).Average();
                double dimStd = StandardDeviation(baseline.Select(f => f[d]).ToList(), dimMean);
                if (dimStd > 0.01 && (worstFeatures[d] - dimMean) / dimStd > ZThreshold)
                {
                    string unit = d == 3 ? "" : "/sec";
                    result.SpikedMetrics.Add(
                        $"{MetricNames[d]}: {worstFeatures[d]:F1}{unit} (baseline: {dimMean:F1}{unit})");
                }
            }

            double severity = (worstScore - threshold) / (threshold > 0.001 ? threshold : 1);
            result.Score = Math.Clamp((int)(severity * 25) + 15, 15, 45);

            return result;
        }

        private static List<double[]> Normalize(List<double[]> raw)
        {
            int dims = raw[0].Length;
            double[] mins = new double[dims];
            double[] maxs = new double[dims];

            for (int d = 0; d < dims; d++)
            {
                mins[d] = double.MaxValue;
                maxs[d] = double.MinValue;
                foreach (var vec in raw)
                {
                    if (vec[d] < mins[d]) mins[d] = vec[d];
                    if (vec[d] > maxs[d]) maxs[d] = vec[d];
                }
            }

            var result = new List<double[]>(raw.Count);
            foreach (var vec in raw)
            {
                var norm = new double[dims];
                for (int d = 0; d < dims; d++)
                {
                    double range = maxs[d] - mins[d];
                    norm[d] = range > 0.001 ? (vec[d] - mins[d]) / range : 0;
                }
                result.Add(norm);
            }
            return result;
        }

        private static double EuclideanDistance(double[] a, double[] b)
        {
            double sum = 0;
            for (int i = 0; i < a.Length; i++)
                sum += (a[i] - b[i]) * (a[i] - b[i]);
            return Math.Sqrt(sum);
        }

        private static double StandardDeviation(List<double> values, double mean)
        {
            double variance = values.Select(v => (v - mean) * (v - mean)).Average();
            return Math.Sqrt(variance);
        }
    }
}
