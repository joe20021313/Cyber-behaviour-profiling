using System;
using System.Collections.Generic;
using System.Linq;

public class BehaviorReport
{
    public int ThreatScore { get; set; }
    public string Rating { get; set; } = "Low";
    public List<string> Reasons { get; set; } = new List<string>();
}

public static class BehaviorAnalyzer
{
    public static BehaviorReport Analyze(ProcessProfile profile)
    {
        var report = new BehaviorReport();

        if (profile.EventTimeline == null || profile.EventTimeline.Count == 0) return report;

        var timeline = profile.EventTimeline.OrderBy(e => e.Timestamp).ToList();

        double score = 0;
        var uniqueIndicators = new HashSet<string>();

        foreach (var ev in timeline)
        {
            if (ev.EventType == "FileRead" || ev.EventType == "FileOpen")
            {
                uniqueIndicators.Add(ev.MatchedIndicator.ToLowerInvariant());
                score += 5;
            }
            else if (ev.EventType == "FileWrite") score += 10;
            else if (ev.EventType == "Registry") score += 10;
            else if (ev.EventType == "ProcessSpawn") score += 15;
            else if (ev.EventType == "SuspiciousCommand") score += 20;
            else if (ev.EventType == "NetworkConnect") score += 15;
            else if (ev.EventType == "DNS_Query") score += 10;
        }

        report.Reasons.Add($"Base Actions: Executed {timeline.Count} monitored events.");

        TimeSpan window = TimeSpan.FromSeconds(2);
        int maxBurst = GetMaxEventsInTimeWindow(timeline, window);

        if (maxBurst >= 5)
        {
            score += 30;
            report.Reasons.Add($"High Velocity: Executed {maxBurst} events in under {window.TotalSeconds} seconds (+30 points).");
        }

        if (uniqueIndicators.Count >= 3)
        {
            score += 25;
            report.Reasons.Add($"Data Hoarding: Touched {uniqueIndicators.Count} different sensitive paths (+25 points).");
        }
        else if (uniqueIndicators.Count == 2)
        {
            score += 10;
            report.Reasons.Add($"Broad Targeting: Touched 2 different sensitive paths (+10 points).");
        }

        if (HasSequence(timeline, "FileRead", "NetworkConnect") || HasSequence(timeline, "FileOpen", "NetworkConnect"))
        {
            score += 40;
            report.Reasons.Add($"Attack Chain: Read sensitive data then connected to network (Possible Exfiltration) (+40 points).");
        }
        if (HasSequence(timeline, "SuspiciousCommand", "ProcessSpawn"))
        {
            score += 25;
            report.Reasons.Add($"Attack Chain: Executed suspicious command then spawned a process (+25 points).");
        }

        double trustMultiplier = 1.0;
        string pName = profile.ProcessName.ToLowerInvariant();

        if (pName.Contains("powershell") || pName.Contains("cmd") || pName.Contains("wscript") || pName.Contains("certutil"))
        {
            trustMultiplier = 1.5;
            report.Reasons.Add($"Process Context: Executed by command-line tool '{profile.ProcessName}' (Score x1.5).");
        }
        else if (pName.Contains("msedge") || pName.Contains("chrome") || pName.Contains("firefox"))
        {
            trustMultiplier = 0.3;
            report.Reasons.Add($"Process Context: Executed by standard browser '{profile.ProcessName}' (Score x0.3).");
        }

        score = score * trustMultiplier;
        report.ThreatScore = (int)Math.Min(Math.Round(score), 100);

        if (report.ThreatScore >= 75) report.Rating = "CRITICAL";
        else if (report.ThreatScore >= 50) report.Rating = "HIGH";
        else if (report.ThreatScore >= 25) report.Rating = "MEDIUM";
        else report.Rating = "LOW";

        return report;
    }

    private static int GetMaxEventsInTimeWindow(List<SuspiciousEvent> events, TimeSpan window)
    {
        if (events.Count == 0) return 0;
        int maxObserved = 1;
        for (int i = 0; i < events.Count; i++)
        {
            int countInWindow = 1;
            for (int j = i + 1; j < events.Count; j++)
            {
                if (events[j].Timestamp - events[i].Timestamp <= window)
                    countInWindow++;
                else
                    break;
            }
            if (countInWindow > maxObserved) maxObserved = countInWindow;
        }
        return maxObserved;
    }

    private static bool HasSequence(List<SuspiciousEvent> events, string eventA, string eventB)
    {
        bool aFound = false;
        foreach (var ev in events)
        {
            if (ev.EventType == eventA) aFound = true;
            if (aFound && ev.EventType == eventB) return true;
        }
        return false;
    }
}