using System.Text;

namespace LogParser.VulnDataUtils;

public readonly struct Location
{
    public string File { get; }
    public int BeginLine { get; }
    public int BeginColumn { get; }
    public int EndLine { get; }
    public int EndColumn { get; }

    public Location(Dictionary<string, string> dict, string keyWord)
    {
        File = dict[$"{keyWord}.File"];
        BeginLine = int.Parse(dict[$"{keyWord}.BeginLine"]);
        BeginColumn = int.Parse(dict[$"{keyWord}.BeginColumn"]);
        EndLine = int.Parse(dict[$"{keyWord}.EndLine"]);
        EndColumn = int.Parse(dict[$"{keyWord}.EndColumn"]);
    }

    public override bool Equals(object? obj)
    {
        if (obj is not Location location)
        {
            return false;
        }

        return location.File.Equals(File) && location.BeginLine.Equals(BeginLine) &&
               location.BeginColumn.Equals(BeginColumn) && location.EndLine.Equals(EndLine) &&
               location.EndColumn.Equals(EndColumn);
    }

    public override string ToString()
    {
        var stringBuilder = new StringBuilder();
        stringBuilder.AppendLine($"    \"File\": {File},");
        stringBuilder.AppendLine($"    \"BeginLine\": {BeginLine},");
        stringBuilder.AppendLine($"    \"BeginColumn\": {BeginColumn},");
        stringBuilder.AppendLine($"    \"EndLine\": {EndLine},");
        stringBuilder.AppendLine($"    \"EndColumn\": {EndColumn}");
        return stringBuilder.ToString();
    }
}