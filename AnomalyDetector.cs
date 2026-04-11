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
        public int ConsecutiveAnomalousWindows { get; set; }
        public bool HasHighSignalFeatureSpike { get; set; }

        public bool IsSustained => ConsecutiveAnomalousWindows >= 2;
    }

    public static class AnomalyDetector
    {
        private const int K = 3;
        private const int MinSamples = 4;
        private const double ZThreshold = 2.5;
        private const double DistanceFloor = 0.5;

        private static readonly string[] MetricNames =
        {
            "Filtered Write Rate",
            "Filtered Delete Rate",
            "Payload Write Rate",
            "Sensitive Access Rate"
        };

        private static readonly double[] MetricScaleFloors = { 3.0, 1.5, 0.15, 0.3 };

        private sealed class ReferenceModel
        {
            public double[] Means { get; set; } = Array.Empty<double>();
            public double[] Scales { get; set; } = Array.Empty<double>();
        }

        private static List<double[]> CopySanitizedHistory(ProcessProfile profile)
        {
            lock (profile.KnnStateLock)
            {
                var history = new List<double[]>();
                foreach (var snapshot in profile.AnomalyHistory)
                {
                    if (snapshot.Length == MetricNames.Length)
                        history.Add((double[])snapshot.Clone());
                }
                return history;
            }
        }

        public static AnomalyResult Evaluate(ProcessProfile profile, ProcessContext ctx)
        {
            _ = ctx;
            var history = CopySanitizedHistory(profile);

            if (history.Count < MinSamples)
                return new AnomalyResult();

            return EvaluateStrongest(history);
        }

        private static AnomalyResult EvaluateStrongest(List<double[]> history)
        {
            var strongestAnomaly = new AnomalyResult();
            AnomalyResult? latestEvaluation = null;

            for (int candidateIndex = MinSamples - 1; candidateIndex < history.Count; candidateIndex++)
            {
                var candidate = history[candidateIndex];
                var reference = history.Take(candidateIndex).ToList();
                var evaluation = EvaluateCandidate(candidate, reference);

                latestEvaluation = evaluation;
                if (!evaluation.AnomalyDetected)
                    continue;

                if (!strongestAnomaly.AnomalyDetected ||
                    evaluation.Score > strongestAnomaly.Score ||
                    (evaluation.Score == strongestAnomaly.Score && evaluation.KnnDistance > strongestAnomaly.KnnDistance))
                {
                    strongestAnomaly = evaluation;
                }
            }

            if (strongestAnomaly.AnomalyDetected)
            {
                int streak = 0;
                for (int i = history.Count - 1; i >= MinSamples - 1; i--)
                {
                    var reference = history.Take(i).ToList();
                    if (reference.Count < K) break;
                    var eval = EvaluateCandidate(history[i], reference);
                    if (!eval.AnomalyDetected) break;
                    streak++;
                }
                strongestAnomaly.ConsecutiveAnomalousWindows = streak;
                return strongestAnomaly;
            }

            return latestEvaluation ?? new AnomalyResult();
        }

        private static AnomalyResult EvaluateCandidate(double[] candidate, List<double[]> reference)
        {
            var result = new AnomalyResult();
            if (reference.Count < K)
                return result;

            var model = BuildReferenceModel(reference);
            var referenceScores = ComputeReferenceScores(reference, model);
            double meanScore = referenceScores.Count > 0 ? referenceScores.Average() : 0.0;
            double stdScore = StandardDeviation(referenceScores, meanScore);
            double threshold = meanScore + ZThreshold * Math.Max(stdScore, DistanceFloor);

            double knnScore = ComputeKnnDistance(candidate, reference, model);

            result.KnnDistance = knnScore;
            result.Threshold = threshold;

            var spikedMetrics = GetSpikedMetricIndexes(candidate, model).ToList();
            if (knnScore <= threshold || spikedMetrics.Count == 0)
                return result;

            result.AnomalyDetected = true;
            result.HasHighSignalFeatureSpike = spikedMetrics.Any(i => i >= 2);
            foreach (int i in spikedMetrics)
                result.SpikedMetrics.Add($"{MetricNames[i]}: {candidate[i]:F1}/sec (baseline: {model.Means[i]:F1}/sec)");

            double noveltyRatio = threshold > 0.001 ? (knnScore - threshold) / threshold : knnScore;
            result.Score = Math.Clamp(15 + (int)Math.Round(Math.Max(0.0, noveltyRatio) * 18.0) + (spikedMetrics.Count * 4), 15, 45);

            return result;
        }

        private static ReferenceModel BuildReferenceModel(List<double[]> reference)
        {
            int dims = MetricNames.Length;
            var means = new double[dims];
            var scales = new double[dims];

            for (int d = 0; d < dims; d++)
            {
                var values = reference.Select(snapshot => snapshot[d]).ToList();
                double mean = values.Count > 0 ? values.Average() : 0.0;
                double std = StandardDeviation(values, mean);

                means[d] = mean;
                scales[d] = Math.Max(std, MetricScaleFloors[d]);
            }

            return new ReferenceModel { Means = means, Scales = scales };
        }

        private static List<double> ComputeReferenceScores(List<double[]> reference, ReferenceModel model)
        {
            var scores = new List<double>();
            for (int i = 0; i < reference.Count; i++)
            {
                var distances = new List<double>();
                for (int j = 0; j < reference.Count; j++)
                {
                    if (i != j)
                        distances.Add(ScaledDistance(reference[i], reference[j], model.Scales));
                }

                distances.Sort();
                if (distances.Count > 0)
                    scores.Add(distances.Take(K).Average());
            }
            return scores;
        }

        private static double ComputeKnnDistance(double[] candidate, List<double[]> reference, ReferenceModel model)
        {
            var distances = reference.Select(s => ScaledDistance(candidate, s, model.Scales)).ToList();
            distances.Sort();
            return distances.Take(K).Average();
        }

        private static IEnumerable<int> GetSpikedMetricIndexes(double[] snapshot, ReferenceModel model)
        {
            int dims = Math.Min(snapshot.Length, MetricNames.Length);
            for (int d = 0; d < dims; d++)
            {
                double threshold = model.Means[d] + model.Scales[d];
                if (snapshot[d] > threshold)
                    yield return d;
            }
        }

        private static double ScaledDistance(double[] a, double[] b, double[] scales)
        {
            double sum = 0.0;
            int length = Math.Min(a.Length, b.Length);
            for (int i = 0; i < length; i++)
            {
                double scale = i < scales.Length ? Math.Max(scales[i], MetricScaleFloors[i]) : DistanceFloor;
                double diff = (a[i] - b[i]) / scale;
                sum += diff * diff;
            }

            return Math.Sqrt(sum);
        }

        private static double StandardDeviation(List<double> values, double mean)
        {
            if (values.Count <= 1) return 0.0;
            double variance = values.Average(v => (v - mean) * (v - mean));
            return Math.Sqrt(variance);
        }
    }
}
