using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Cyber_behaviour_profiling
{
    public class ProcessBaseline
    {
        public double[][] Snapshots { get; set; } = Array.Empty<double[]>();
        public string Source { get; set; } = "builtin";
        public string? RecordedAt { get; set; }
    }

    public class BaselineStore
    {
        public Dictionary<string, ProcessBaseline> Baselines { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public class AnomalyResult
    {
        public bool AnomalyDetected { get; set; }
        public List<string> SpikedMetrics { get; set; } = new();
        public double KnnDistance { get; set; }
        public double Threshold { get; set; }
        public int Score { get; set; }
        public int ConsecutiveAnomalousWindows { get; set; }
        public bool HasHighSignalFeatureSpike { get; set; }
        public bool IsBurstDetection { get; set; }
        public bool TripwireFired { get; set; }
        public string TripwireReason { get; set; } = "";

        public bool BaselineUsed { get; set; }

        public bool IsSustained => ConsecutiveAnomalousWindows >= 2;
    }

    public static class AnomalyDetector
    {
        private const int K          = 5;
        private const int Knear      = 2;
        private const int MinSamples = 2;

        private static double _zThreshold    = 2.5;
        private static double _distanceFloor = 0.5;

        private static readonly string[] MetricNames =
        {
            "Filtered Write Rate",
            "Filtered Delete Rate",
            "Payload Write Rate",
            "Sensitive Access Rate"
        };

        private static double[] _metricScaleFloors = { 0.1, 0.05, 0.02, 0.05 };

        private static Dictionary<string, ProcessBaseline> _baselines =
            new(StringComparer.OrdinalIgnoreCase);

        private static int _maxBaselineSnapshots = 50;

        public static int MaxSnapshots => _maxBaselineSnapshots;

        public static int MinVectorsRequired => K + 1;

        private const double PayloadRateCap        = 0.1;
        private const double UserPayloadRateCap    = 5.0;
        private const double SensitiveRateCap      = 0.05;
        private const double UserSensitiveRateCap  = 2.0;

        private const double TripwireWriteRate     = 25.0;
        private const double TripwireDeleteRate    = 15.0;
        private const double TripwirePayloadRate   = 8.0;
        private const double TripwireSensitiveRate = 4.0;

        private static readonly double[] TripwireThresholds =
        {
            TripwireWriteRate,
            TripwireDeleteRate,
            TripwirePayloadRate,
            TripwireSensitiveRate
        };

        public static void ConfigureScaleFloors(double[] floors)
        {
            if (floors.Length >= MetricNames.Length)
                _metricScaleFloors = floors.Take(MetricNames.Length).ToArray();
        }

        public static void ConfigureMaxSnapshots(int maxSnapshots)
        {
            _maxBaselineSnapshots = Math.Max(maxSnapshots, MinVectorsRequired);
        }

        public static void ConfigureDetector(double zThreshold, double distanceFloor)
        {
            if (zThreshold    > 0) _zThreshold    = zThreshold;
            if (distanceFloor > 0) _distanceFloor = distanceFloor;
        }

        private sealed class ReferenceModel
        {
            public double[] Means  { get; set; } = Array.Empty<double>();
            public double[] Scales { get; set; } = Array.Empty<double>();
        }

        public static void LoadBaselines(Dictionary<string, ProcessBaseline> baselines)
        {
            var sanitized = new Dictionary<string, ProcessBaseline>(StringComparer.OrdinalIgnoreCase);

            if (baselines == null)
            {
                _baselines = sanitized;
                return;
            }

            foreach (var entry in baselines)
            {
                string key = Path.GetFileNameWithoutExtension(entry.Key ?? string.Empty).ToLowerInvariant();
                if (string.IsNullOrWhiteSpace(key))
                    continue;

                ProcessBaseline baseline = entry.Value ?? new ProcessBaseline();
                var snapshots = (baseline.Snapshots ?? Array.Empty<double[]>())
                    .Where(s => s != null && s.Length >= MetricNames.Length)
                    .Select(s => s.Take(MetricNames.Length).ToArray())
                    .ToList();

                if (snapshots.Count > _maxBaselineSnapshots)
                    snapshots = snapshots[^_maxBaselineSnapshots..];

                if (snapshots.Count < MinVectorsRequired)
                {
                    InvestigationLog.Write(
                        $"Skipping baseline '{key}': requires at least {MinVectorsRequired} snapshots, found {snapshots.Count}.");
                    continue;
                }

                double payloadCap = baseline.Source == "user" ? UserPayloadRateCap : PayloadRateCap;
                double sensitiveCap = baseline.Source == "user" ? UserSensitiveRateCap : SensitiveRateCap;

                foreach (var snap in snapshots)
                {
                    snap[2] = Math.Min(snap[2], payloadCap);
                    snap[3] = Math.Min(snap[3], sensitiveCap);
                }

                var zeroOnlyMetrics = Enumerable.Range(0, MetricNames.Length)
                    .Where(d => snapshots.All(s => s[d] <= 0.0))
                    .Select(d => MetricNames[d])
                    .ToList();

                if (zeroOnlyMetrics.Count > 0)
                {
                    InvestigationLog.Write(
                        $"Baseline '{key}' has zero-only metric dimensions: {string.Join(", ", zeroOnlyMetrics)}.");
                }

                sanitized[key] = new ProcessBaseline
                {
                    Source = string.IsNullOrWhiteSpace(baseline.Source) ? "builtin" : baseline.Source,
                    RecordedAt = baseline.RecordedAt,
                    Snapshots = snapshots.Select(s => (double[])s.Clone()).ToArray()
                };
            }

            _baselines = sanitized;
        }

        public static ProcessBaseline? GetBaseline(string processName)
        {
            string key = Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();
            return _baselines.TryGetValue(key, out var b) ? b : null;
        }

        public static IReadOnlyDictionary<string, ProcessBaseline> AllBaselines => _baselines;

        public static ProcessBaseline? CaptureBaseline(ProcessProfile profile)
            => CaptureBaseline(profile, startIndex: 0, meaningfulOnly: false);

        public static ProcessBaseline? CaptureBaseline(
            ProcessProfile profile,
            int startIndex,
            bool meaningfulOnly)
        {
            var history = CopySanitizedHistory(profile);

            if (startIndex > 0)
            {
                if (startIndex >= history.Count)
                    history = new List<double[]>();
                else
                    history = history.Skip(startIndex).ToList();
            }

            if (meaningfulOnly)
                history = history.Where(IsMeaningfulSnapshot).ToList();

            if (history.Count < MinVectorsRequired)
                return null;

            var snapshots = history.Count > _maxBaselineSnapshots
                ? history.GetRange(history.Count - _maxBaselineSnapshots, _maxBaselineSnapshots)
                : history;

            return new ProcessBaseline
            {
                Snapshots = snapshots.Select(s => (double[])s.Clone()).ToArray(),
                Source    = "user"
            };
        }

        public static int CountMeaningfulSnapshots(ProcessProfile profile, int startIndex = 0)
        {
            var history = CopySanitizedHistory(profile);
            if (startIndex > 0)
            {
                if (startIndex >= history.Count)
                    return 0;
                history = history.Skip(startIndex).ToList();
            }

            return history.Count(IsMeaningfulSnapshot);
        }

        private static bool IsMeaningfulSnapshot(double[] snapshot)
        {
            if (snapshot.Length < MetricNames.Length)
                return false;

            for (int i = 0; i < MetricNames.Length; i++)
                if (snapshot[i] > 0.0)
                    return true;

            return false;
        }

        private static List<double[]> CopySanitizedHistory(ProcessProfile profile)
        {
            lock (profile.KnnStateLock)
            {
                var result = new List<double[]>(profile.AnomalyHistory.Count);
                foreach (var snap in profile.AnomalyHistory)
                    if (snap.Length == MetricNames.Length)
                        result.Add((double[])snap.Clone());
                return result;
            }
        }

        public static AnomalyResult Evaluate(ProcessProfile profile, ProcessContext ctx)
        {
            string key = Path.GetFileNameWithoutExtension(profile.ProcessName ?? "").ToLowerInvariant();
            ProcessBaseline? baseline = GetBaseline(key);

            var snapshotResult = EvaluateSnapshotStream(profile, baseline);

            var burstResult = EvaluateBurst(profile, baseline);

            var result = PickStrongest(snapshotResult, burstResult);
            result.BaselineUsed = baseline != null;
            return result;
        }

        private static AnomalyResult EvaluateSnapshotStream(ProcessProfile profile, ProcessBaseline? baseline)
        {
            var history = CopySanitizedHistory(profile);
            return history.Count < MinSamples
                ? new AnomalyResult()
                : EvaluateStrongest(history, baseline);
        }

        private static AnomalyResult EvaluateStrongest(List<double[]> history, ProcessBaseline? baseline)
        {
            var strongest = new AnomalyResult();
            AnomalyResult? latest = null;

            for (int ci = MinSamples - 1; ci < history.Count; ci++)
            {
                var candidate  = history[ci];
                var reference  = history.Take(ci).ToList();
                var evaluation = EvaluateCandidate(candidate, reference, baseline);

                latest = evaluation;
                if (!evaluation.AnomalyDetected) continue;

                if (!strongest.AnomalyDetected ||
                    evaluation.Score > strongest.Score ||
                    (evaluation.Score == strongest.Score &&
                     evaluation.KnnDistance > strongest.KnnDistance))
                {
                    strongest = evaluation;
                }
            }

            if (strongest.AnomalyDetected)
            {
                int streak = 0;
                for (int i = history.Count - 1; i >= MinSamples - 1; i--)
                {
                    var reference = history.Take(i).ToList();
                    if (reference.Count < K) break;
                    if (!EvaluateCandidate(history[i], reference, baseline).AnomalyDetected) break;
                    streak++;
                }
                strongest.ConsecutiveAnomalousWindows = streak;
                return strongest;
            }

            return latest ?? new AnomalyResult();
        }

        private static AnomalyResult EvaluateBurst(ProcessProfile profile, ProcessBaseline? baseline)
        {
            var history = CopySanitizedHistory(profile);
            double[] peak = new double[MetricNames.Length];
            bool hasHistory = history.Count > 0;

            foreach (var snap in history)
            {
                for (int d = 0; d < MetricNames.Length; d++)
                    if (snap[d] > peak[d]) peak[d] = snap[d];
            }

            if (!hasHistory)
            {

                double elapsed = Math.Max(0.5, (DateTime.Now - profile.FirstSeen).TotalSeconds);
                peak = new[]
                {
                    profile.TotalFilteredWrites        / elapsed,
                    profile.TotalFilteredDeletes       / elapsed,
                    profile.TotalPayloadLikeWrites     / elapsed,
                    profile.TotalSensitiveAccessEvents / elapsed
                };
            }

            var result = EvaluateCandidate(peak, baseline == null ? history : new List<double[]>(), baseline);
            if (result.AnomalyDetected)
                result.IsBurstDetection = true;
            return result;
        }

        private static AnomalyResult EvaluateCandidate(
            double[] candidate, List<double[]> sessionHistory, ProcessBaseline? baseline)
        {
            var result = new AnomalyResult();
            bool allowTripwire = baseline == null;
            if (allowTripwire && TryEvaluateTripwire(candidate, out string tripwireReason, out int tripwireMetric,
                out double tripwireValue, out double tripwireThreshold))
            {
                result.AnomalyDetected = true;
                result.TripwireFired = true;
                result.TripwireReason = tripwireReason;
                result.Score = 36;
                result.HasHighSignalFeatureSpike = tripwireMetric >= 2;
                result.SpikedMetrics.Add(
                    $"{MetricNames[tripwireMetric]}: {tripwireValue:F1}/sec (tripwire: {tripwireThreshold:F1}/sec)");
            }

            List<double[]> fullRef;
            if (baseline?.Snapshots is { Length: > 0 })
            {
                fullRef = new List<double[]>(baseline.Snapshots.Length);
                foreach (var s in baseline.Snapshots)
                    if (s.Length == MetricNames.Length) fullRef.Add(s);

                if (baseline.Source != "user")
                {
                    double payloadCap   = PayloadRateCap;
                    double sensitiveCap = SensitiveRateCap;
                    if (candidate.Length > 2 && candidate[2] > payloadCap)
                    {
                        candidate = (double[])candidate.Clone();
                        candidate[2] = payloadCap;
                        if (candidate.Length > 3) candidate[3] = Math.Min(candidate[3], sensitiveCap);
                    }
                    else if (candidate.Length > 3 && candidate[3] > sensitiveCap)
                    {
                        candidate = (double[])candidate.Clone();
                        candidate[3] = sensitiveCap;
                    }
                }
            }
            else
            {
                fullRef = sessionHistory;
            }

            if (fullRef.Count < K) return result;

            var model        = BuildReferenceModel(fullRef);
            var refScores    = ComputeReferenceScores(fullRef, model);
            double meanScore = refScores.Count > 0 ? refScores.Average() : 0.0;
            double stdScore  = StandardDeviation(refScores, meanScore);
            double threshold = meanScore + _zThreshold * Math.Max(stdScore, _distanceFloor);
            double knnScore  = ComputeKnnDistance(candidate, fullRef, model);

            result.KnnDistance = knnScore;
            result.Threshold   = threshold;

            var spiked = GetSpikedMetricIndexes(candidate, fullRef, model).ToList();
            if (knnScore <= threshold) return result;

            result.AnomalyDetected          = true;
            result.HasHighSignalFeatureSpike = result.HasHighSignalFeatureSpike || spiked.Any(i => i >= 2);
            foreach (int i in spiked)
            {
                string detail =
                    $"{MetricNames[i]}: {candidate[i]:F1}/sec (baseline: {model.Means[i]:F1}/sec)";
                if (!result.SpikedMetrics.Any(metric =>
                        metric.StartsWith($"{MetricNames[i]}:", StringComparison.OrdinalIgnoreCase)))
                {
                    result.SpikedMetrics.Add(detail);
                }
            }

            double novelty = threshold > 0.001
                ? (knnScore - threshold) / threshold
                : knnScore;
            int knnScoreValue = Math.Clamp(
                15 + (int)Math.Round(Math.Max(0.0, novelty) * 18.0) + spiked.Count * 4,
                15, 45);
            result.Score = Math.Max(result.Score, knnScoreValue);

            return result;
        }

        private static bool TryEvaluateTripwire(
            IReadOnlyList<double> candidate,
            out string reason,
            out int metricIndex,
            out double metricValue,
            out double threshold)
        {
            reason = "";
            metricIndex = -1;
            metricValue = 0.0;
            threshold = 0.0;

            int dims = Math.Min(candidate.Count, Math.Min(MetricNames.Length, TripwireThresholds.Length));
            double strongestRatio = 1.0;

            for (int i = 0; i < dims; i++)
            {
                double currentThreshold = TripwireThresholds[i];
                if (currentThreshold <= 0.0)
                    continue;

                double value = candidate[i];
                if (value < currentThreshold)
                    continue;

                double ratio = value / currentThreshold;
                if (metricIndex == -1 || ratio > strongestRatio)
                {
                    metricIndex = i;
                    metricValue = value;
                    threshold = currentThreshold;
                    strongestRatio = ratio;
                }
            }

            if (metricIndex == -1)
                return false;

            reason =
                $"{MetricNames[metricIndex]} {metricValue:F1}/sec exceeded tripwire {threshold:F1}/sec";
            return true;
        }

        private static AnomalyResult PickStrongest(AnomalyResult a, AnomalyResult b)
        {
            if (a.AnomalyDetected && b.AnomalyDetected)
                return a.Score >= b.Score ? a : b;
            if (a.AnomalyDetected) return a;
            if (b.AnomalyDetected) return b;

            return a.KnnDistance >= b.KnnDistance ? a : b;
        }

        private static ReferenceModel BuildReferenceModel(List<double[]> reference)
        {
            int dims   = MetricNames.Length;
            var means  = new double[dims];
            var scales = new double[dims];

            for (int d = 0; d < dims; d++)
            {
                var values = reference.Select(s => s[d]).ToList();
                double mean = values.Average();
                double std  = StandardDeviation(values, mean);
                means[d]  = mean;
                scales[d] = Math.Max(std, _metricScaleFloors[d]);
            }
            return new ReferenceModel { Means = means, Scales = scales };
        }

        private static List<double> ComputeReferenceScores(List<double[]> reference, ReferenceModel model)
        {
            var scores = new List<double>(reference.Count);
            for (int i = 0; i < reference.Count; i++)
            {
                var dists = new List<double>(reference.Count - 1);
                for (int j = 0; j < reference.Count; j++)
                    if (i != j) dists.Add(ScaledDistance(reference[i], reference[j], model.Scales));
                dists.Sort();
                if (dists.Count > 0) scores.Add(dists.Take(Knear).Average());
            }
            return scores;
        }

        private static double ComputeKnnDistance(double[] candidate, List<double[]> reference, ReferenceModel model)
        {
            var dists = reference.Select(s => ScaledDistance(candidate, s, model.Scales)).ToList();
            dists.Sort();
            return dists.Take(Knear).Average();
        }

        private static IEnumerable<int> GetSpikedMetricIndexes(
            double[] candidate, List<double[]> reference, ReferenceModel model)
        {
            var nearest = reference
                .OrderBy(s => ScaledDistance(candidate, s, model.Scales))
                .Take(Knear)
                .ToList();

            int dims = Math.Min(candidate.Length, MetricNames.Length);
            for (int d = 0; d < dims; d++)
            {
                double localMax = nearest.Count > 0 ? nearest.Max(s => s[d]) : model.Means[d];
                if (candidate[d] > localMax + 2.0 * model.Scales[d])
                    yield return d;
            }
        }

        private static double ScaledDistance(double[] a, double[] b, double[] scales)
        {
            double sum = 0.0;
            int len    = Math.Min(a.Length, b.Length);
            for (int i = 0; i < len; i++)
            {
                double scale = i < scales.Length
                    ? scales[i]
                    : _distanceFloor;
                if (scale <= 0.0)
                    scale = _distanceFloor;
                double diff = (a[i] - b[i]) / scale;
                sum += diff * diff;
            }
            return Math.Sqrt(sum);
        }

        private static double StandardDeviation(List<double> values, double mean)
        {
            if (values.Count <= 1) return 0.0;
            return Math.Sqrt(values.Average(v => (v - mean) * (v - mean)));
        }
    }
}
