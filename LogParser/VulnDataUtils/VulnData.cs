/*
using System.Text;

namespace LogParser.VulnDataUtils;

public readonly struct VulnData
{
    public string Version { get; }
    public string Id { get; }
    public string GroupId { get; }
    public string ScanMode { get; }
    public string Class { get; }
    public string Type { get; }
    public string IsSuspected { get; }
    public string IsSecondOrder { get; }
    public string IsSuppressed { get; }
    public DataTracePoint VulnerableExpression { get; }
    public DataTracePoint EntryPoint { get; }
    public string AdditionalConditions { get; }
    public Exploit Exploit { get; }
    public DataTracePoint[] TaintDataEntries { get; }
    public DataTracePoint[] DataTrace { get; }
    public string BestPlaceToFix { get; }

    public VulnData(Dictionary<string, string> dict)
    {
        Version = dict["Version"];
        Id = dict["Id"];
        GroupId = dict["GroupId"];
        ScanMode = dict["ScanMode"];
        Class = dict["Class"];
        Type = dict["Type"];
        IsSuspected = dict["IsSuspected"];
        IsSecondOrder = dict["IsSecondOrder"];
        IsSuppressed = dict["IsSuppressed"];
        VulnerableExpression = new DataTracePoint(dict, StringConstants.VulnerableExpressionLiteral);
        EntryPoint = new DataTracePoint(dict, StringConstants.EntryPointLiteral);
        AdditionalConditions = dict["AdditionalConditions"];
        Exploit = new Exploit(dict);
        TaintDataEntries = CreateArray(StringConstants.TaintDataEntriesLiteral);
        DataTrace = CreateArray(StringConstants.DataTraceLiteral);
        BestPlaceToFix = dict["BestPlaceToFix"];

        DataTracePoint[] CreateArray(string key)
        {
            var list = new List<DataTracePoint>();
            for (var i = 0;; i++)
            {
                var keyInternal = $"{key}{i}";
                if (dict.Any(pair => pair.Key.StartsWith(keyInternal)))
                {
                    list.Add(new DataTracePoint(dict, keyInternal));
                    continue;
                }
                break;
            }
            return list.ToArray();
        }
    }

    public override bool Equals(object? obj)
    {
        if (obj is not VulnData vulnData)
        {
            return false;
        }

        var scanModeEqual = vulnData.ScanMode.Equals(ScanMode);
        var classEqual = vulnData.Class.Equals(Class);
        var typeEqual = vulnData.Type.Equals(Type);
        var vulnerableExpressionEqual = vulnData.VulnerableExpression.Equals(VulnerableExpression);
        var entryPointEqual = vulnData.EntryPoint.Equals(EntryPoint);
        var taintDataEntriesEqual = vulnData.TaintDataEntries.Length == TaintDataEntries.Length;
        foreach (var point in vulnData.TaintDataEntries)
        {
            taintDataEntriesEqual = taintDataEntriesEqual && TaintDataEntries.Contains(point);
        }
        var dataTraceEqual = vulnData.DataTrace.Length == DataTrace.Length;
        foreach (var point in vulnData.DataTrace)
        {
            dataTraceEqual = taintDataEntriesEqual && DataTrace.Contains(point);
        }

        return scanModeEqual && classEqual && typeEqual && vulnerableExpressionEqual && entryPointEqual &&
               taintDataEntriesEqual && dataTraceEqual;
    }

    public override string ToString()
    {
        var stringBuilder = new StringBuilder();
        stringBuilder.AppendLine("{");
        stringBuilder.AppendLine($"  \"GroupId\": {GroupId},");
        stringBuilder.AppendLine($"  \"ScanMode\": {ScanMode},");
        stringBuilder.AppendLine($"  \"Type\": {Type},");
        stringBuilder.AppendLine($"  \"VulnerableExpression.Value\": {VulnerableExpression.Value},");
        stringBuilder.AppendLine("  \"Entrypoint\": {");
        stringBuilder.Append(EntryPoint.ToString());
        stringBuilder.AppendLine("  },");
        stringBuilder.AppendLine("  \"TaintDataEntries\":");
        foreach (var point in TaintDataEntries)
        {
            stringBuilder.AppendLine("  {");
            stringBuilder.Append(point.ToString());
            stringBuilder.AppendLine("  },");
        }
        stringBuilder.AppendLine("  \"DataTrace\":");
        foreach (var point in DataTrace)
        {
            stringBuilder.AppendLine("  {");
            stringBuilder.Append(point.ToString());
            stringBuilder.AppendLine("  },");
        }
        stringBuilder.AppendLine("{");
        return stringBuilder.ToString();
    }
}
*/