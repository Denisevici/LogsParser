using Newtonsoft.Json.Linq;

namespace LogParser.VulnDataUtils;

public class AiVulnData : VulnDataFather
{
    private static readonly string[] UsefullHandlerKeys =
        { "Version", "Id", "GroupId", "ScanMode", "Class", "Type", "IsSuspected", "IsSecondOrder", "IsSuppressed", "AdditionalConditions" };

    private static readonly string[] HandlerKeysToSkip = { "Function", "Visualization", "StackTrace" };

    public AiVulnData(Dictionary<string, object> dict) : base(dict)
    {
        var vulnDict = new Dictionary<string, string>();
        foreach (var item in dict)
        {
            if (HandlerKeysToSkip.Contains(item.Key))
            {
                continue;
            }

            if (UsefullHandlerKeys.Contains(item.Key))
            {
                vulnDict[item.Key] = item.Value.ToString();
                continue;
            }

            if (item.Value is JObject jObject)
            {
                SendJObjectToDict(vulnDict, item.Key, jObject);
                continue;
            }

            if (item.Value is JArray jArray)
            {
                var i = 0;
                foreach (var jArrayItem in jArray)
                {
                    if (jArrayItem is JObject @object)
                    {
                        SendJObjectToDict(vulnDict, item.Key, @object, i);
                        i++;
                    }
                    else
                    {
                        break;
                    }
                }
                continue;
            }
            throw new ArgumentException($"Unexpected value of type {item.Value} for key {item.Key}");
        }
        InitVulnData(vulnDict);
    }

    private void SendJObjectToDict(Dictionary<string, string> dict, string mainKey, JObject jObject, int index = Int32.MinValue)
    {
        foreach (var jObjectItem in jObject)
        {
            var key = $"{mainKey}{(index >= 0 ? index.ToString() : string.Empty)}.{jObjectItem.Key}";
            dict[key] = jObjectItem.Value.ToString();
        }
    }
}