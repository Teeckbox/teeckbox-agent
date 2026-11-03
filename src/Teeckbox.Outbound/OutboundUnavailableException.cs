namespace Teeckbox.Outbound;

/// <summary>
/// The system cannot be called: it is disabled, a setting or a secret is missing or unusable, or its answer cannot be read.
/// The message names the cause and never holds a secret.
/// </summary>
public sealed class OutboundUnavailableException(string message, Exception? inner = null) : Exception(message, inner);
