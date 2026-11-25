<#
.SYNOPSIS
  LV NEXUS: create the read-only GCP service account and grant its organization-level READ roles.
  Run by a GCP organization administrator (Google Cloud CLI signed in). Shows the plan and asks before changing anything.
  It never grants write roles and never touches workloads.

.EXAMPLE
  .\setup-gcp-reader.ps1 -OrgId 123456789012 -Project lv-cloudnexus-prod -BillingDataset billing
  .\setup-gcp-reader.ps1 -OrgId 123456789012 -Project lv-cloudnexus-prod -BillingDataset billing -CreateKey -KeyPath C:\cloudnexus-secrets\gcp\cloudnexus-reader.json
#>
param(
  [Parameter(Mandatory)][ValidatePattern('^\d+$')][string]$OrgId,
  [Parameter(Mandatory)][string]$Project,
  [string]$BillingDataset = "",
  [string]$AccountName = "cloudnexus-reader",
  [switch]$CreateKey,
  [string]$KeyPath = "C:\cloudnexus-secrets\gcp\cloudnexus-reader.json"
)
$ErrorActionPreference = "Stop"
if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) { throw "Google Cloud CLI (gcloud) is not installed or not on PATH." }

$email = "$AccountName@$Project.iam.gserviceaccount.com"
$member = "serviceAccount:$email"
$apis = "cloudresourcemanager.googleapis.com","compute.googleapis.com","logging.googleapis.com","monitoring.googleapis.com",
        "cloudasset.googleapis.com","securitycenter.googleapis.com","bigquery.googleapis.com","iam.googleapis.com"
$orgRoles = "roles/browser","roles/cloudasset.viewer","roles/compute.viewer","roles/logging.viewer","roles/monitoring.viewer",
            "roles/securitycenter.findingsViewer","roles/iam.securityReviewer"
$projectRoles = "roles/serviceusage.serviceUsageConsumer","roles/bigquery.jobUser"

Write-Host "`nPlan (read-only access only):" -ForegroundColor Cyan
Write-Host "  Signed in as : $(gcloud config get-value account 2>$null)"
Write-Host "  Enable APIs  : $($apis -join ', ') in $Project"
Write-Host "  Create SA    : $email (if missing)"
Write-Host "  Org $OrgId roles : $($orgRoles -join ', ')"
Write-Host "  Project roles: $($projectRoles -join ', ')"
if ($BillingDataset) { Write-Host "  BigQuery     : Data Viewer on $Project`:$BillingDataset" }
if ($CreateKey) { Write-Host "  Key file     : $KeyPath (protect the folder; rotate every 90 days)" }
if ((Read-Host "`nType YES to apply") -ne "YES") { Write-Host "Nothing changed."; exit 0 }

function Run([string[]]$cmd) {
  Write-Host "> gcloud $($cmd -join ' ')" -ForegroundColor DarkGray
  & gcloud @cmd
  if ($LASTEXITCODE -ne 0) { throw "gcloud failed: $($cmd -join ' ')" }
}

Run (@("services","enable") + $apis + @("--project=$Project"))
$exists = gcloud iam service-accounts list --project=$Project --filter="email:$email" --format="value(email)"
if (-not $exists) { Run @("iam","service-accounts","create",$AccountName,"--project=$Project","--display-name=LV NEXUS read-only") }
foreach ($r in $orgRoles) { Run @("organizations","add-iam-policy-binding",$OrgId,"--member=$member","--role=$r","--condition=None","--quiet") }
foreach ($r in $projectRoles) { Run @("projects","add-iam-policy-binding",$Project,"--member=$member","--role=$r","--condition=None","--quiet") }
if ($BillingDataset) {
  # dataset-level read access for the billing export
  $tmp = New-TemporaryFile
  & bq show --format=prettyjson "$Project`:$BillingDataset" | Set-Content $tmp
  $ds = Get-Content $tmp -Raw | ConvertFrom-Json
  if (-not ($ds.access | Where-Object { $_.userByEmail -eq $email })) {
    $ds.access += [pscustomobject]@{ role = "READER"; userByEmail = $email }
    $ds | ConvertTo-Json -Depth 20 | Set-Content $tmp
    & bq update --source $tmp "$Project`:$BillingDataset"
    if ($LASTEXITCODE -ne 0) { throw "bq update failed: grant BigQuery Data Viewer on the dataset in the console instead." }
  }
  Remove-Item $tmp
}
if ($CreateKey) {
  $dir = Split-Path $KeyPath
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  Run @("iam","service-accounts","keys","create",$KeyPath,"--iam-account=$email")
  Write-Host "Key written to $KeyPath. Restrict the folder to SYSTEM, Administrators and the CloudNexus service account." -ForegroundColor Yellow
}
Write-Host "`nDone. In backend\.env set:" -ForegroundColor Green
Write-Host "  GCP_ENABLED=true"
Write-Host "  GCP_ORGANIZATION_ID=$OrgId"
if ($CreateKey) { Write-Host "  GCP_CREDENTIALS_FILE=$KeyPath" }
Write-Host "  GCP_BILLING_QUERY_PROJECT=$Project"
if ($BillingDataset) { Write-Host "  GCP_BILLING_EXPORT_TABLE=$Project.$BillingDataset.<gcp_billing_export_v1_... table name shown in BigQuery>" }
