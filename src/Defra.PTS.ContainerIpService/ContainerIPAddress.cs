using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using System.Net;
using System.Diagnostics.CodeAnalysis;

namespace Defra.PTS.ContainerIpService
{
    [ExcludeFromCodeCoverage]
    public static class GetContainerIPAddress
    {
        [FunctionName("GetContainerIPAddress")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "getContainerIPAddress")] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("Start getting ip address");

            var keyVaultName = Environment.GetEnvironmentVariable("keyVaultName");
            var azureTenantId = Environment.GetEnvironmentVariable("AzureTenantId");
            var containerName = Environment.GetEnvironmentVariable("ContainerName");
            var resourceGroup = Environment.GetEnvironmentVariable("ContainerResourceGroupName");
            var subscriptionId = Environment.GetEnvironmentVariable("Subscription");

            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));

            var azureApplicationId = (await keyVaultClient.GetSecretAsync($"https://{keyVaultName}.vault.azure.net/secrets/AdoSpClientId")).Value;
            var azurePassword = (await keyVaultClient.GetSecretAsync($"https://{keyVaultName}.vault.azure.net/secrets/AdoSpClientSecret")).Value;

            var securePassword = new NetworkCredential("", azurePassword).SecurePassword;
            var credentials = new AzureCredentials(
                new ServicePrincipalLoginInformation
                {
                    ClientId = azureApplicationId,
                    ClientSecret = azurePassword
                },
                azureTenantId,
                AzureEnvironment.AzureGlobalCloud);

            var azure = Azure
                .Authenticate(credentials)
                .WithSubscription(subscriptionId);

            var containerGroup = await azure.ContainerGroups.GetByResourceGroupAsync(resourceGroup, containerName);
            var ipAddress = containerGroup.IPAddress;

            log.LogInformation("End getting ip address");
            return new OkObjectResult(ipAddress);
        }
    }
}
