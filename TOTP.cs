using OtpNet;
using QRCoder;

namespace Useful.Toolkit;

/// <summary>
/// Helper methods for time-based one-time-passwords using common parameters
/// (hash mode SHA1 and window of one step in each direction).
/// </summary>
public static class TOTP
{
    /// <summary>
    /// Randomly generates a new key.
    /// </summary>
    public static byte[] GenerateKey()
        => KeyGeneration.GenerateRandomKey();
    
    /// <summary>
    /// Checks whether the code is valid for the key and returns the used timestamp.
    /// </summary>
    public static bool VerifyCode(byte[] key, string code, out long timestamp)
        => new Totp(key).VerifyTotp(code, out timestamp, new VerificationWindow(1, 1));
    
    /// <summary>
    /// Generates a key string to add the key to an authenticator app.
    /// </summary>
    public static string GetKeyString(byte[] key)
        => Base32Encoding.ToString(key);
    
    /// <summary>
    /// Generates a URL to add the key to an authenticator app.
    /// </summary>
    public static string GetKeyUrl(byte[] key, string domain, string username)
        => $"otpauth://totp/{domain}:{username}?secret={GetKeyString(key)}&issuer={domain}";
    
    /// <summary>
    /// Generates a QR code to add the key to an authenticator app and returns it as raw bytes.
    /// </summary>
    public static byte[] GetKeyQRBytes(byte[] key, string domain, string username)
    {
        var content = GetKeyUrl(key, domain, username);
        using var generator = new QRCodeGenerator();
        using var qr = generator.CreateQrCode(content, QRCodeGenerator.ECCLevel.Q);
        using var png = new PngByteQRCode(qr);
        return png.GetGraphic(20);
    }
    
    /// <summary>
    /// Generates a QR code to add the key to an authenticator app and returns an HTML image source for it using base64.
    /// </summary>
    public static string GetKeyQRBase64(byte[] key, string domain, string username)
    {
        var bytes = GetKeyQRBytes(key, domain, username);
        return $"data:image/png;base64,{Convert.ToBase64String(bytes)}";
    }
}
