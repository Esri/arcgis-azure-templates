<#
   Copyright 2021 Esri
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.​
#>

param(
    [Parameter(Mandatory=$false)]
    [System.String]
    $CertificatePassword,

    [Parameter(Mandatory=$false)]
    [System.String]
    $ServerMachineNames,

    [Parameter(Mandatory=$false)]
    [System.String]
    $PortalMachineNames,

    [Parameter(Mandatory=$false)]
    [System.String]
    $FileShareName,

    [Parameter(Mandatory=$false)]
    [System.String]
    $OverrideCertificates = "false",
    
    [Parameter(Mandatory=$false)]
    [System.String]
    $DebugMode
)

function Get-FQDN
{    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$MachineName
    )
    if($MachineName -as [ipaddress]){
        $Dns = $MachineName
    }else{
        [bool]$ResolvedDns = $false
        [int]$NumOfDnsResolutionAttempts = 0
        $Dns = $Null
        while((-not $ResolvedDns) -and ($NumOfDnsResolutionAttempts -lt 10))
        {        
            $DnsRecord = $null
            Try {
                if(Get-Command 'Resolve-DnsName' -ErrorAction Ignore) {
                    $DnsRecord = Resolve-DnsName -Name $MachineName -Type ANY -ErrorAction Ignore | Select-Object -First 1                     
                    if($DnsRecord -eq $null) {
                        $DnsRecord = Resolve-DnsName -Name $MachineName -Type A -ErrorAction Ignore                
                    }
                }
                if($DnsRecord -eq $null) {
                    $machine = (Get-WmiObject -Class Win32_ComputerSystem).Name
                    $domain = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $MachineName).DNSDomain
                    $Dns = "$($machine).$($domain)"
                    $ResolvedDns = $true
                }
            }
            Catch {
                Write-Verbose "Error Resolving DNS $($_)"            
            }
            if($DnsRecord -ne $null) {
                [void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.WindowsAzure.ServiceRuntime')
                $UseIP = $false
                if (('Microsoft.WindowsAzure.ServiceRuntime.RoleEnvironment' -as [type]) -and ([Microsoft.WindowsAzure.ServiceRuntime.RoleEnvironment]::DeploymentId -ne $null))
                {
                    $UseIP = $true
                    Write-Verbose "Running on Microsoft Azure Cloud Service VM (Web/Worker) Role. Using IP Address instead of hostnames"
                }
                $Dns = if($UseIP) { $DnsRecord.IPAddress } else { $DnsRecord.Name }
                if($Dns -ne $null -and $Dns.Length -gt 0)
                {
                    $ResolvedDns = $true
                }
                else {
                    Start-Sleep -Seconds 15
                }
            } elseif(-not($ResolvedDns)) {
                Start-Sleep -Seconds 15
            }
            $NumOfDnsResolutionAttempts++
        }
    }
    if(-not $Dns){         
        throw "Unable to resolve DNS for $MachineName"          
    }
    $Dns
}

function Output-Certificate{
    param(
        [System.String]
        $OutputCertCerFilePath
    )

    $c = gc $OutputCertCerFilePath -Encoding Byte  
    Write-Host ([System.Convert]::ToBase64String($c)) -NoNewline
    Write-Host "###DATA###" -NoNewline

}

function Create-SelfSignedCertificateWithSANs
{
    param(
        [System.String]
        $OutputCertFilePath,

        [System.String]
        $OutputCertCerFilePath,

        [System.String]
        $CertificatePassword,

        $DnsNames
    )
    
    Write-Verbose "Generating a self signed certificate with the DNS names $($DnsNames -join ',') for the Endpoint $($EndPoint)"
    if([Environment]::OSVersion.Version.Major -ge 10) {
        $Cert = New-SelfSignedCertificate -DnsName $DnsNames -KeyUsage None -CertStoreLocation Cert:\LocalMachine\My -NotBefore ([System.DateTime]::UtcNow).AddDays(-5) -NotAfter ([System.DateTime]::UtcNow).AddYears(5)
    }else {
        $Cert = New-SelfSignedCertificate -DnsName @($DnsNames) -CertStoreLocation Cert:\LocalMachine\My
    }
    Export-Certificate -Type CERT -Cert $cert -FilePath $OutputCertCerFilePath
    
    Write-Verbose "Saving (exporting) file to $CertificateFilePath"
    Export-PfxCertificate -Force -Password (ConvertTo-SecureString -AsPlainText $CertificatePassword -Force) -FilePath $OutputCertFilePath -Cert "Cert:\LocalMachine\My\$($Cert.Thumbprint)" | Out-Null
    Write-Verbose "Saved cert with thumbprint $($Cert.Thumbprint) file to $CertificateFilePath"
    
    Output-Certificate -OutputCertCerFilePath $OutputCertCerFilePath
}

$FileShareLocalPath = (Join-Path $env:SystemDrive $FileShareName)
$CertsFolder = Join-Path $FileShareLocalPath 'Certs'
if(-not(Test-Path $CertsFolder)){
    New-Item -Path $CertsFolder -ItemType directory -ErrorAction Stop | Out-Null
}

if($ServerMachineNames){
    $CertificateName  = 'SSLCertificateForServer'
    $ServerOutputCertFilePath = Join-Path $CertsFolder "$($CertificateName).pfx"
    $ServerOutputCertCerFilePath = Join-Path $CertsFolder "$($CertificateName).cer"
    $ServerValidCert = $true
    $ServerDnsNames = @()
    
    ($ServerMachineNames -split ',') | ForEach-Object { $ServerDnsNames += Get-FQDN $_ }

    if((Test-Path $ServerOutputCertFilePath) -and (Test-Path $ServerOutputCertCerFilePath)){
        $ServerCertDNSNameList = (Get-PfxCertificate -FilePath $ServerOutputCertCerFilePath).DnsNameList
        $ServerDnsNames | Foreach-Object {
            if($ServerValidCert){
                $ServerValidCert = $ServerCertDNSNameList -icontains $_ 
            }
        }
    }else{
        $ServerValidCert = $false
    }

    if(($OverrideCertificates -ieq "True") -or -not($ServerValidCert)){
        Create-SelfSignedCertificateWithSANs -OutputCertFilePath $ServerOutputCertFilePath -OutputCertCerFilePath $ServerOutputCertCerFilePath -CertificatePassword $CertificatePassword -DnsNames $ServerDnsNames | Out-Null
    }else{
        Output-Certificate -OutputCertCerFilePath $ServerOutputCertCerFilePath
    }
}

if($PortalMachineNames){
    $CertificateName  = 'SSLCertificateForPortal'
    $PortalOutputCertFilePath = Join-Path $CertsFolder "$($CertificateName).pfx"
    $PortalOutputCertCerFilePath = Join-Path $CertsFolder "$($CertificateName).cer"
    $PortalValidCert = $true
    $PortalDnsNames = @()
    
    ($PortalMachineNames -split ',') | ForEach-Object { $PortalDnsNames += Get-FQDN $_ }

    if((Test-Path $PortalOutputCertFilePath) -and (Test-Path $PortalOutputCertCerFilePath)){
        $PortalCertDNSNameList = (Get-PfxCertificate -FilePath $PortalOutputCertCerFilePath).DnsNameList
        $PortalDnsNames | Foreach-Object {
            if($PortalValidCert){
                $PortalValidCert = $PortalCertDNSNameList -icontains $_ 
            }
        }
    }else{
        $PortalValidCert = $false
    }

    if(($OverrideCertificates -ieq "True") -or -not($PortalValidCert)){
        Create-SelfSignedCertificateWithSANs -OutputCertFilePath $PortalOutputCertFilePath -OutputCertCerFilePath $PortalOutputCertCerFilePath -CertificatePassword $CertificatePassword -DnsNames $PortalDnsNames | Out-Null
    }else{
        Output-Certificate -OutputCertCerFilePath $PortalOutputCertCerFilePath
    }
}