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

}
