using System.Text;
using System.Text.RegularExpressions;
using LogParser.VulnDataUtils;
using static Newtonsoft.Json.JsonConvert;

namespace LogParser;

class Program
{
    private const string LogYearLiteral = "2024";
    private const string BestPlaceToFixLiteral = "BestPlaceToFix";
    private const string RegexKey = "key";
    private const string RegexValue = "value";
    
    static void Main(string[] args)
    {
        var path1 = "C:\\Work\\Projects\\logs\\compare\\WebGoatPHP-master_all_fixes_1\\Vulnerabilities.log";
        var path3 = "C:\\Work\\Projects\\logs\\compare\\WebGoatPHP-master_all_fixes_3\\Vulnerabilities.log";
        TryParseJsaVulnLog(path1, out var path1Vulns);
        TryParseJsaVulnLog(path3, out var path3Vulns);
        
        var (oneHasNo, threeHasNo) = Compare(path1Vulns, path3Vulns);

        var pathToFile = "C:\\Users\\dkomerzan\\RiderProjects\\LogParser\\LogParser\\data.txt";
        var stringBuilder = new StringBuilder();
        stringBuilder.AppendLine($"jsa has no {threeHasNo.Count}");
        stringBuilder.AppendLine($"ai has no {oneHasNo.Count}");
        foreach (var vulnData in threeHasNo)
        {
            stringBuilder.AppendLine("one has not this vuln:");
            stringBuilder.AppendLine();
            stringBuilder.AppendLine(vulnData.ToString());
        }
        foreach (var vulnData in oneHasNo)
        {
            stringBuilder.AppendLine("three has not this vuln:");
            stringBuilder.AppendLine();
            stringBuilder.AppendLine(vulnData.ToString());
        }
        File.Delete(pathToFile);
        File.WriteAllText(pathToFile, stringBuilder.ToString());
    }

    static bool TryParseJsaVulnLog(string path, out List<VulnDataFather> vulnData)
    {
        if (!File.Exists(path))
        {
            vulnData = default;
            return false;
        }
        
        vulnData = new List<VulnDataFather>();
        var dict = new Dictionary<string, object>();
        var fatherKey = string.Empty;
        var taintDataEntriesIndex = 0;
        var dataTraceIndex = 0;
        var pattern = new Regex($@"""(?'{RegexKey}'\w+)"":\s(?'{RegexValue}'.+)");

        foreach (var line in File.ReadAllLines(path))
        {
            if (line.StartsWith("}"))
            {
                if (dict.Count != 0)
                {
                    vulnData.Add(new JsaVulnData(dict));
                    dict.Clear();
                }
                fatherKey = string.Empty;
                continue;
            }

            var trimmedLine = line.TrimStart();
            
            if (trimmedLine.StartsWith($"\"{StringConstants.VulnerableExpressionLiteral}"))
            {
                fatherKey = StringConstants.VulnerableExpressionLiteral;
                continue;
            }
            else if (trimmedLine.StartsWith($"\"{StringConstants.EntryPointLiteral}"))
            {
                fatherKey = StringConstants.EntryPointLiteral;
                continue;
            }
            else if (trimmedLine.StartsWith($"\"{StringConstants.AdditionalConditionLiteral}"))
            {
                fatherKey = string.Empty;
            }
            else if (trimmedLine.StartsWith($"\"{StringConstants.ExploitLiteral}"))
            {
                fatherKey = StringConstants.ExploitLiteral;
                continue;
            }
            else if (trimmedLine.StartsWith($"\"{StringConstants.TaintDataEntriesLiteral}"))
            {
                fatherKey = StringConstants.TaintDataEntriesLiteral;
                taintDataEntriesIndex = -1;
                continue;
            }
            else if (trimmedLine.StartsWith($"\"{StringConstants.DataTraceLiteral}"))
            {
                fatherKey = StringConstants.DataTraceLiteral;
                dataTraceIndex = -1;
                continue;
            }
            else if (trimmedLine.StartsWith($"\"{StringConstants.ValueLiteral}") && fatherKey == StringConstants.DataTraceLiteral)
            {
                dataTraceIndex++;
            }
            else if (trimmedLine.StartsWith($"\"{StringConstants.ValueLiteral}") && fatherKey == StringConstants.TaintDataEntriesLiteral)
            {
                taintDataEntriesIndex++;
            }
            else if (trimmedLine.StartsWith($"\"{BestPlaceToFixLiteral}"))
            {
                fatherKey = string.Empty;
            }

            var matches = pattern.Matches(trimmedLine);
            foreach (Match match in matches)
            {
                var index = fatherKey == StringConstants.DataTraceLiteral ? dataTraceIndex.ToString() :
                    fatherKey == StringConstants.TaintDataEntriesLiteral ? taintDataEntriesIndex.ToString() :
                    string.Empty;
                var dot = fatherKey == string.Empty ? string.Empty : ".";
                dict.Add(
                    $"{fatherKey}{index}{dot}{match.Groups[RegexKey]}",
                    match.Groups[RegexValue].ToString().TrimStart('"', ' ').TrimEnd('"', ',', ' '));
            }
        }

        return true;
    }

    static bool TryParseAiVulnLog(string path, out List<VulnDataFather> vulnData)
    {
        if (!File.Exists(path))
        {
            vulnData = default;
            return false;
        }

        vulnData = new ();
        foreach (var line in File.ReadAllLines(path))
        {
            if (line.Contains("Weakness"))
            {
                continue;
            }

            var lineData = line.Replace("False", "false");
            lineData = lineData.Replace("True", "true");
            lineData = lineData.Replace("None", "null");
            lineData = lineData.Replace("\\x00", "");
            lineData = lineData.TrimEnd(',');
            var data = DeserializeObject<Dictionary<string, object>>(lineData);
            vulnData.Add(new AiVulnData(data));
        }

        return true;
    }

    static (List<VulnDataFather> beforeHasNo, List<VulnDataFather> afterHasNo) Compare(List<VulnDataFather> vulnDataBefore,
        List<VulnDataFather> vulnDataAfter)
    {
        var afterHasNo = new List<VulnDataFather>();
        foreach (var vulnData in vulnDataBefore)
        {
            if (vulnDataAfter.Contains(vulnData))
            {
                continue;
            }

            afterHasNo.Add(vulnData);
        }

        var beforeHasNo = new List<VulnDataFather>();
        foreach (var vulnData in vulnDataAfter)
        {
            if (vulnDataBefore.Contains(vulnData))
            {
                continue;
            }

            beforeHasNo.Add(vulnData);
        }

        return (beforeHasNo, afterHasNo);
    }
}