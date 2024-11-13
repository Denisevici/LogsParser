namespace LogParser.VulnDataUtils;

public class JsaVulnData : VulnDataFather
{
    public JsaVulnData(Dictionary<string, object> dict) : base(dict)
    {
        Dictionary<string, string> newDict = new();
        try
        {
            foreach (var (key, value) in dict)
            {
                newDict[key] = value as string;
            }
        }
        catch (Exception)
        {
            throw new ArgumentException("Invalid argument, expected all values from dict to be strings");
        }
        
        InitVulnData(newDict);
    }
}