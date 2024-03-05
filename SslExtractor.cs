/*
                TXG0Fk3
                https://github.com/txg0fk3
                https://discord.com/users/txg0fk3
                Copyright © 2024, Skyrus Labz. Todos os direitos reservados.
                04/03/2024
*/

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

class Program
{
    static async Task Main()
    {
        string url = "https://www.bing.com"; // Substitua pela URL desejada

        try
        {
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;

            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(url);

                // Obter as informações do certificado do servidor
                X509Certificate2 certificate = GetCertificate(response);

                // Exibir as informações do certificado
                DisplayCertificateInfo(certificate);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro: {ex.Message}");
        }
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

    private static void DisplayCertificateInfo(X509Certificate2 certificate)
    {
        if (certificate != null)
        {
            Console.WriteLine("Informações do Certificado SSL:");
            Console.WriteLine($"Emissor: {certificate.Issuer}");
            Console.WriteLine($"Assunto: {certificate.Subject}");
            Console.WriteLine($"Válido de: {certificate.NotBefore} até: {certificate.NotAfter}");
        }
        else
        {
            Console.WriteLine("Não foi possível obter informações do certificado.");
        }
    }
}
