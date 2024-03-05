/*
                TXG0Fk3
                https://github.com/txg0fk3
                https://discord.com/users/txg0fk3
                Copyright © 2024, Skyrus Labz. Todos os direitos reservados.
                04/03/2024
*/

using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

public class CertificateInfoModule
{
    public static async Task<string> GetCertificateInfoJson(string url)
    {
        try
        {
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;

            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(url);

                // Obter as informações do certificado do servidor
                X509Certificate2 certificate = GetCertificate(response);

                // Verificar se o certificado foi obtido com sucesso antes de criar a string JSON
                if (certificate != null)
                {
                    // Obter a string JSON com as informações do certificado
                    return GetCertificateInfoJson(certificate);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro: {ex.Message}");
        }

        return null;
    }

    private static X509Certificate2 GetCertificate(HttpResponseMessage response)
    {
        // Obter o certificado do servidor a partir da resposta HTTP
        if (response?.RequestMessage != null)
        {
            var requestUri = response.RequestMessage.RequestUri;
            using (var tcpClient = new TcpClient(requestUri.Host, requestUri.Port))
            using (var sslStream = new SslStream(tcpClient.GetStream(), false, (sender, certificate, chain, sslPolicyErrors) => true))
            {
                sslStream.AuthenticateAsClient(requestUri.Host);
                return new X509Certificate2(sslStream.RemoteCertificate);
            }
        }
        return null;
    }

    private static string GetCertificateInfoJson(X509Certificate2 certificate)
    {
        // Extrair as informações do certificado
        var certificateInfo = new
        {
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            Thumbprint = certificate.Thumbprint,
            SerialNumber = certificate.SerialNumber,
            NotBefore = certificate.NotBefore,
            NotAfter = certificate.NotAfter,
            Version = certificate.Version,
            PublicKeyAlgorithm = certificate.PublicKey?.Oid.FriendlyName,
            SignatureAlgorithm = certificate.SignatureAlgorithm?.FriendlyName,
            KeyUsage = certificate.Extensions["2.5.29.15"]?.Critical,
            ExtendedKeyUsage = GetExtendedKeyUsage(certificate),
        };

        // Converter o objeto para uma string JSON formatada
        return JsonSerializer.Serialize(certificateInfo, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string[] GetExtendedKeyUsage(X509Certificate2 certificate)
    {
        var extendedKeyUsage = new List<string>();

        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid.Value.Equals("2.5.29.37")) // OID para Extended Key Usage
            {
                var extendedKeyUsageExtension = new X509EnhancedKeyUsageExtension(extension, false);
                foreach (var oid in extendedKeyUsageExtension.EnhancedKeyUsages)
                {
                    extendedKeyUsage.Add(oid.FriendlyName);
                }
            }
        }

        return extendedKeyUsage.ToArray();
    }
}
