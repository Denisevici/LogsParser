using System.Text;

namespace LogParser.VulnDataUtils;

public readonly struct DataTracePoint
{
    public string Value { get; }
    public Location Location { get; }

    public DataTracePoint(Dictionary<string, string> dict, string keyWord)
    {
        Value = dict[$"{keyWord}.{StringConstants.ValueLiteral}"];
        Location = new Location(dict, keyWord);
    }

    public override bool Equals(object? obj)
    {
        if (obj is not DataTracePoint dataTracePoint)
        {
            return false;
            
        }

        return dataTracePoint.Value.Equals(Value) && dataTracePoint.Location.Equals(Location);
    }

    public override string ToString()
    {
        var stringBuilder = new StringBuilder();
        stringBuilder.AppendLine($"    \"Value\": {Value}");
        stringBuilder.Append(Location.ToString());
        return stringBuilder.ToString();
    }
}