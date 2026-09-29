using System.Diagnostics;
using ModelContextProtocol.Server;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Mvc;

[McpServerToolType]
public class Tools
{
    private static object Parse(string payload)
    {
        return JsonConvert.DeserializeObject(payload, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
    }

    [McpServerTool]
    public static string Run(string command)
    {
        Process.Start("cmd.exe", "/c " + command);
        Parse(command);
        return "ok";
    }
}

[ApiController]
public class HomeController : ControllerBase
{
    [HttpGet("/parse")]
    public object Get(string payload)
    {
        return JsonConvert.DeserializeObject(payload);
    }
}
