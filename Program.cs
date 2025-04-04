using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

class Program
{
    private static readonly string keyVaultUrl = "https://kv-elims-1.vault.azure.net/";
    private static readonly string keyName = "kv-elims-test";

    static void Main()
    {
        // Validate that the variables are loaded
        if (string.IsNullOrEmpty(keyVaultUrl) || string.IsNullOrEmpty(keyName))
        {
            Console.WriteLine("Error: KEY_VAULT_URL or KEY_NAME not found in .env file.");
            return;
        }

        // Sample JSON object
        var jsonObject = new { Name = "Ebola", Value = 42 };
        string jsonString = JsonSerializer.Serialize(jsonObject);
        Console.WriteLine("Original JSON: " + jsonString);

        // Step 1: Generate a hash of the JSON object
        byte[] jsonBytes = Encoding.UTF8.GetBytes(jsonString);
        byte[] hash;
        using (var sha256 = SHA256.Create())
        {
            hash = sha256.ComputeHash(jsonBytes);
        }
        Console.WriteLine("Hash: " + Convert.ToBase64String(hash));

        // Step 2: Sign the hash with Azure Key Vault
        byte[] signature = SignDataWithKeyVault(hash);
        Console.WriteLine("Signature (store in DB): " + Convert.ToBase64String(signature));

        // Step 3: Verify the signature online
        Console.WriteLine("Signature Verified Online: " + VerifySignatureOnline(hash, signature));

        // Step 4: Retrieve the public key
        JsonWebKey publicKey = GetPublicKeyFromKeyVault();
        string publicKeyJson = JsonSerializer.Serialize(publicKey);
        Console.WriteLine("Public Key JSON (store in DB): " + publicKeyJson);

        // Step 5: Verify the signature offline
        Console.WriteLine("Signature Verified Offline: " + VerifySignatureOffline(hash, signature, publicKey));
    }

    static byte[] SignDataWithKeyVault(byte[] hash)
    {
        var credential = new DefaultAzureCredential();
        var keyClient = new KeyClient(new Uri(keyVaultUrl), credential);
        KeyVaultKey key = keyClient.GetKey(keyName).Value;
        var cryptoClient = new CryptographyClient(key.Id, credential);
        SignResult signResult = cryptoClient.Sign(SignatureAlgorithm.RS256, hash);
        return signResult.Signature;
    }

    static JsonWebKey GetPublicKeyFromKeyVault()
    {
        var credential = new DefaultAzureCredential();
        var keyClient = new KeyClient(new Uri(keyVaultUrl), credential);
        KeyVaultKey key = keyClient.GetKey(keyName).Value;
        return key.Key;
    }

    static bool VerifySignatureOnline(byte[] hash, byte[] signature)
    {
        var credential = new DefaultAzureCredential();
        var cryptoClient = new CryptographyClient(new Uri($"{keyVaultUrl}keys/{keyName}"), credential);
        VerifyResult verifyResult = cryptoClient.Verify(SignatureAlgorithm.RS256, hash, signature);
        return verifyResult.IsValid;
    }    

    static bool VerifySignatureOffline(byte[] hash, byte[] signature, JsonWebKey publicKey)
    {
        var rsa = RSA.Create();
        var rsaParameters = new RSAParameters
        {
            Modulus = publicKey.N,
            Exponent = publicKey.E
        };
        rsa.ImportParameters(rsaParameters);
        return rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}