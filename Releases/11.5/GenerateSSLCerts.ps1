param(
    [switch]
    $UseInternalSelfSignedCertificate,

    [Parameter(Mandatory=$false)]
    [System.String]
    $ServerInternalCertificateFileName,

    [Parameter(Mandatory=$false)]
    [System.String]
    $PortalInternalCertificateFileName,

    [Parameter(Mandatory=$false)]
    [System.String]
    $ExternalDNSHostName,

    [Parameter(Mandatory=$false)]
    [System.String]
    $ServerRole,

    [Parameter(Mandatory=$false)]
    [System.String]
    $ServerContext,

    [Parameter(Mandatory=$false)]
    [System.String]
    $PortalContext,

    [Parameter(Mandatory=$false)]
    [System.String]
    $CertificatePassword,

    [Parameter(Mandatory=$false)]
    [System.String]
    $ServerMachineNames,

    [Parameter(Mandatory=$false)]
    [System.String]
    $PortalMachineNames,

    [switch]
    $UseExistingFileShare,

    [switch]
    $UseExistingFileShareMachineOfBaseDeployment,

    [Parameter(Mandatory=$false)]
    [System.String]
    $FileShareName,

    [Parameter(Mandatory=$false)]
    [System.String]
    $FileShareMachineName,

    [Parameter(Mandatory=$false)]
    [System.String]
    $FileSharePath,

    [Parameter(Mandatory=$false)]
    [System.String]
    $ArcGISRunAsAccountCredentialUserName,

    [Parameter(Mandatory=$false)]
    [System.String]
    $ArcGISRunAsAccountCredentialPassword
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

function Output-Certificate
{
    param(
        [System.String]
        $OutputCertCerFilePath
    )

    $c = Get-Content $OutputCertCerFilePath -Encoding Byte  
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
    Export-Certificate -Type CERT -Cert $cert -FilePath $OutputCertCerFilePath | Out-Null
    
    Write-Verbose "Saving (exporting) file to $CertificateFilePath"
    Export-PfxCertificate -Force -Password (ConvertTo-SecureString -AsPlainText $CertificatePassword -Force) -FilePath $OutputCertFilePath -Cert "Cert:\LocalMachine\My\$($Cert.Thumbprint)" | Out-Null
    Write-Verbose "Saved cert with thumbprint $($Cert.Thumbprint) file to $CertificateFilePath"
    
    Output-Certificate -OutputCertCerFilePath $OutputCertCerFilePath
}

$FileShareLocalPath = (Join-Path $env:SystemDrive $FileShareName)
$CertsFolder = Join-Path $FileShareLocalPath 'Certs'
$ServerCertsFolder = $CertsFolder
$PortalCertsFolder = $CertsFolder
if($UseExistingFileShare)
{
    if($UseExistingFileShareMachineOfBaseDeployment){
        $FileSharePath = "\\$FileShareMachineName\$FileShareName"
    }

    $DeploymentFolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    # Mount the PS Drive 
     
    $ArcGISRunAsAccountCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ArcGISRunAsAccountCredentialUserName, (ConvertTo-SecureString $ArcGISRunAsAccountCredentialPassword -AsPlainText -Force) )

    $PsDrive = New-PsDrive -Name X -Root $FileSharePath -PSProvider FileSystem -Credential $ArcGISRunAsAccountCredential -ErrorAction Stop
    Write-Verbose "Mapped Drive $($PsDrive.Name) to $FileSharePath"
    $CertsFolder = "X:\$($DeploymentFolderName)"

    if($ServerMachineNames -and $ServerContext)
    {
        $ServerCertsFolder = Join-Path $CertsFolder $ServerContext
        if(-not(Test-Path $ServerCertsFolder)){
            New-Item -Path $ServerCertsFolder -ItemType directory -ErrorAction Stop | Out-Null
        }

        # if notebook server
        if($ServerRole -ieq "NotebookServer"){
            $NBServerDirFolder = Join-Path $ServerCertsFolder 'server-dirs'
            if(-not(Test-Path $NBServerDirFolder)){
			    New-Item -Path $NBServerDirFolder -ItemType directory -ErrorAction Stop | Out-Null
		    }
            $NBWorkspaceFolder = Join-Path $NBServerDirFolder 'arcgisworkspace'
            if(-not(Test-Path $NBWorkspaceFolder)){
                New-Item -Path $NBWorkspaceFolder -ItemType directory -ErrorAction Stop | Out-Null
            }
        }
    }

    if($PortalMachineNames -and $PortalContext)
    {
        $PortalCertsFolder = Join-Path $CertsFolder $PortalContext
        if(-not(Test-Path $PortalCertsFolder)){
            New-Item -Path $PortalCertsFolder -ItemType directory -ErrorAction Stop | Out-Null
        }
    }
}else{
    if(-not(Test-Path $CertsFolder)){
        New-Item -Path $CertsFolder -ItemType directory -ErrorAction Stop | Out-Null
    }
}

if($UseInternalSelfSignedCertificate)
{
    if($ServerMachineNames){
        $CertificateName  = 'SSLCertificateForServer'
        $ServerOutputCertFilePath = Join-Path $ServerCertsFolder "$($CertificateName).pfx"
        $ServerOutputCertCerFilePath = Join-Path $ServerCertsFolder "$($CertificateName).cer"
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

        if(-not($ServerValidCert)){
            Create-SelfSignedCertificateWithSANs -OutputCertFilePath $ServerOutputCertFilePath -OutputCertCerFilePath $ServerOutputCertCerFilePath -CertificatePassword $CertificatePassword -DnsNames $ServerDnsNames | Out-Null
        }else{
            Output-Certificate -OutputCertCerFilePath $ServerOutputCertCerFilePath
        }
    }

    if($PortalMachineNames){
        $CertificateName  = 'SSLCertificateForPortal'
        $PortalOutputCertFilePath = Join-Path $PortalCertsFolder "$($CertificateName).pfx"
        $PortalOutputCertCerFilePath = Join-Path $PortalCertsFolder "$($CertificateName).cer"
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

        if(-not($PortalValidCert)){
            Create-SelfSignedCertificateWithSANs -OutputCertFilePath $PortalOutputCertFilePath -OutputCertCerFilePath $PortalOutputCertCerFilePath -CertificatePassword $CertificatePassword -DnsNames $PortalDnsNames | Out-Null
        }else{
            Output-Certificate -OutputCertCerFilePath $PortalOutputCertCerFilePath
        }
    }
}
else
{
    $ServerCertificateName  = 'SSLCertificateForServer'
    if($ServerInternalCertificateFileName){
        $ServerOutputCertFilePath = Join-Path $ServerCertsFolder "$($ServerCertificateName).pfx"
        Copy-Item $ServerInternalCertificateFileName -Destination $ServerOutputCertFilePath | Out-Null
    }
    
    $PortalCertificateName  = 'SSLCertificateForPortal'
    if($PortalInternalCertificateFileName){
        $PortalOutputCertFilePath = Join-Path $PortalCertsFolder "$($PortalCertificateName).pfx"
        Copy-Item $PortalInternalCertificateFileName -Destination $PortalOutputCertFilePath | Out-Null
    }
}

if($UseExistingFileShare)
{
    Write-Verbose "Removing Temporary Mapped Drive 'X'"
    Remove-PsDrive -Name 'X' -Force       
}