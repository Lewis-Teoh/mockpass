<#
.SYNOPSIS
  Build mockpass Docker image, push to ECR, force ECS redeploy.

.EXAMPLE
  ./deploy.ps1 -AccountId 123456789012
  ./deploy.ps1 -AccountId 123456789012 -SkipDeploy
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$AccountId,

    [string]$Region   = "ap-southeast-1",
    [string]$Profile  = "lorenz-aws-staging",
    [string]$Repo     = "hsa-ectd-mockpassnodeapp",
    [string]$Cluster  = "hsa-ectd-cluster",
    [string]$Service  = "MockpassNodeApp-Service",
    [string]$Tag      = "latest",

    # skip the ECS force-new-deployment step (build + push only)
    [switch]$SkipDeploy
)

$ErrorActionPreference = "Stop"

$registry  = "$AccountId.dkr.ecr.$Region.amazonaws.com"
$localImg  = "${Repo}:${Tag}"
$remoteImg = "$registry/${Repo}:${Tag}"

Write-Host "==> ECR login ($registry)" -ForegroundColor Cyan
aws ecr get-login-password --region $Region --profile $Profile |
    docker login --username AWS --password-stdin $registry
if ($LASTEXITCODE -ne 0) { throw "ECR login failed" }

Write-Host "==> Build $localImg (linux/amd64)" -ForegroundColor Cyan
docker build --platform linux/amd64 -t $localImg .
if ($LASTEXITCODE -ne 0) { throw "docker build failed" }

Write-Host "==> Tag -> $remoteImg" -ForegroundColor Cyan
docker tag $localImg $remoteImg
if ($LASTEXITCODE -ne 0) { throw "docker tag failed" }

Write-Host "==> Push $remoteImg" -ForegroundColor Cyan
docker push $remoteImg
if ($LASTEXITCODE -ne 0) { throw "docker push failed" }

if ($SkipDeploy) {
    Write-Host "==> SkipDeploy set - done (image pushed, ECS not redeployed)" -ForegroundColor Yellow
    return
}

Write-Host "==> Force ECS redeploy ($Service)" -ForegroundColor Cyan
aws ecs update-service `
    --cluster $Cluster `
    --service $Service `
    --force-new-deployment `
    --region $Region `
    --profile $Profile `
    --query "service.deployments[0].{status:status,desired:desiredCount,running:runningCount}" `
    --output table
if ($LASTEXITCODE -ne 0) { throw "ecs update-service failed" }

Write-Host "==> Done. Watch rollout:" -ForegroundColor Green
Write-Host "    aws ecs describe-services --cluster $Cluster --services $Service --region $Region --profile $Profile --query 'services[0].deployments' --output table"
