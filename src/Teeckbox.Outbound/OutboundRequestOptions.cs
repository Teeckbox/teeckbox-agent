namespace Teeckbox.Outbound;

/// <summary>Options set on a request to tell the HTTP client how to send it.</summary>
public static class OutboundRequestOptions
{
    /// <summary>
    /// The request may reach a loopback, private or link-local address: the administrator allowed it for this connection.
    /// Without it, an address of that kind is refused at the moment of connecting.
    /// </summary>
    public static readonly HttpRequestOptionsKey<bool> AllowInternalAddress = new("Teeckbox.AllowInternalAddress");
}
