public class CookieAuthProvider : CookieAuthenticationProvider
{
    protected Microsoft.ApplicationInsights.TelemetryClient telemetry =
        new Microsoft.ApplicationInsights.TelemetryClient(Microsoft.ApplicationInsights.Extensibility.TelemetryConfiguration.Active);

    public override void ResponseSignIn(CookieResponseSignInContext context)
    {
        //Logs Exemplo
        var req = context.Request;

        var data = new System.Collections.Generic.Dictionary<string, object>();
        data.Add("URI", req.Uri.ToString());
        data.Add("Host", req.Host.ToString());
        data.Add("LocalIpAddress", req.LocalIpAddress.ToString());
        data.Add("RemoteIpAddress", req.RemoteIpAddress.ToString());

        var headers = new System.Collections.Generic.Dictionary<string, string>();
        foreach (var key in req.Headers.Keys)
            headers.Add(key, req.Headers[key]);
        data.Add(nameof(req.Headers), headers);

        var cookies = new System.Collections.Generic.Dictionary<string, string>();
        foreach (var ck in req.Cookies)
            cookies.Add(ck.Key, ck.Value);
        data.Add(nameof(req.Cookies), cookies);

        telemetry.TrackTrace($"NewResponseSignIn: {Newtonsoft.Json.JsonConvert.SerializeObject(data)}");

        //Regra para definir cookie domain null, se estiver no proxy reverso(X - Forwarded - Server)
        
        var currentHost = context.Request.Uri.Host;
        var forwardedServer = context.Request.Headers["X-Forwarded-Server"];

        if (!string.IsNullOrEmpty(forwardedServer))
            currentHost = forwardedServer;

        if (currentHost.EndsWith("fixeddomain.com"))
            context.CookieOptions.Domain = ".fixeddomain.com";
        else
            context.CookieOptions.Domain = null;

        base.ResponseSignIn(context);
    }
}
