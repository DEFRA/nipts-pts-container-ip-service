using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.ContainerInstance;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Defra.PTS.ContainerIpService;

[ExcludeFromCodeCoverage]
public class GetContainerIPAddress
{
    private readonly ILogger<GetContainerIPAddress> _logger;

    public GetContainerIPAddress(ILogger<GetContainerIPAddress> logger)
    {
        _logger = logger;
    }

    [Function("GetContainerIPAddress")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "getContainerIPAddress")] HttpRequest req)
    {
        _logger.LogInformation("Start getting ip address");

        var keyVaultName = Environment.GetEnvironmentVariable("keyVaultName");
        var azureTenantId = Environment.GetEnvironmentVariable("AzureTenantId");
        var containerName = Environment.GetEnvironmentVariable("ContainerName");
        var resourceGroup = Environment.GetEnvironmentVariable("ContainerResourceGroupName");
        var subscriptionId = Environment.GetEnvironmentVariable("Subscription");

        var defaultCredential = new DefaultAzureCredential();

        var secretClient = new SecretClient(
            new Uri($"https://{keyVaultName}.vault.azure.net/"),
            defaultCredential);

        var azureApplicationId = (await secretClient.GetSecretAsync("AdoSpClientId")).Value.Value;
        var azurePassword = (await secretClient.GetSecretAsync("AdoSpClientSecret")).Value.Value;

        var spCredential = new ClientSecretCredential(azureTenantId, azureApplicationId, azurePassword);

        var armClient = new ArmClient(spCredential, subscriptionId);
        var subscription = await armClient.GetDefaultSubscriptionAsync();
        var resourceGroupResource = await subscription.GetResourceGroupAsync(resourceGroup);
        var containerGroup = await resourceGroupResource.Value.GetContainerGroups().GetAsync(containerName);

        var ipAddress = containerGroup.Value.Data.IPAddress?.IP?.ToString();

        _logger.LogInformation("End getting ip address");
        return new OkObjectResult(ipAddress);
    }
}
