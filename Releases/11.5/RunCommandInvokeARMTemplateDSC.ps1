param(
    [Parameter(Mandatory=$false)]
    [System.String]
    $Version = '11.5',

    [Parameter(Mandatory=$True)]
    [System.String]
    $DSCZipFileUrl,

    [Parameter(Mandatory=$True)]
    [System.String]
    $ConfigurationName,

    [Parameter(Mandatory=$False)]
    [System.String]
    $IsBaseDeployment = 'false',

    [Parameter(Mandatory=$False)]
    [System.String]
    $IsMultiTier = 'false',

    [parameter(Mandatory = $False)]
	[System.String]
    $ServerRole,

    [parameter(Mandatory = $False)]
	[System.String]
    $ServerFunctions,

    [Parameter(Mandatory=$False)]
    [System.String]
    $ServerContext,

    [Parameter(Mandatory=$False)]
    [System.String]
    $GeoeventContext,

    [Parameter(Mandatory=$False)]
    [System.String]
    $ServiceCredential,

    [Parameter(Mandatory=$false)]
    [System.String]
    $ServiceCredentialIsDomainAccount,

    [Parameter(Mandatory=$false)]
    [System.String]
    $MachineAdministratorCredential,

    [Parameter(Mandatory=$false)]
    [System.String]
    $SiteAdministratorCredential,

    [Parameter(Mandatory=$false)]
    [System.String]
    $IsAddingServersOrRegisterEGDB = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $IsUpdatingCertificates = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $ServerMachineNames,

    [Parameter(Mandatory=$False)]
    [System.String]
    $ExternalDNSHostName,

    [Parameter(Mandatory=$false)]
    [System.String]
    $PrivateDNSHostName,

    [Parameter(Mandatory=$false)]
    [System.String]
    $UseExistingFileShare = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $UseFileShareMachineOfBaseDeployment= 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $FileShareMachineName,

    [Parameter(Mandatory=$False)]
    [System.String]
    $FileShareName,

    [Parameter(Mandatory=$false)]
    [System.String]
    $FileSharePath,

    [Parameter(Mandatory=$false)]
    [System.String]
    $UseCloudStorage = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $UseAzureFiles = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $CloudStorageAuthenticationType,

    [Parameter(Mandatory=$false)]
    [System.String]
    $StorageAccountServicePrincipalTenantId,

    [Parameter(Mandatory=$false)]
    [System.String]
    $StorageAccountServicePrincipalAuthorityHost,

    [Parameter(Mandatory=$false)]
    [System.String]
    $StorageAccountServicePrincipalCredential,

    [Parameter(Mandatory=$false)]
    [System.String]
    $StorageAccountUserAssignedIdentityClientId,

    [Parameter(Mandatory=$false)]
    [System.String]
    $StorageAccountCredential,

    [Parameter(Mandatory=$false)]
    [System.String]
    $EnableLogHarvesterPlugin = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $ServerLicenseFileUrl,

    [Parameter(Mandatory=$false)]
    [System.String]
    $PublicKeySSLCertificateFileUrl,

    [Parameter(Mandatory=$false)]
    [System.String]
    $ServerInternalCertificatePassword,

    [Parameter(Mandatory=$false)]
    [System.String]
    $FederateSite = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $PortalMachineNamesOnHostingServer,

    [Parameter(Mandatory=$false)]
    [System.String]
    $GisServerMachineNamesOnHostingServer,

    [Parameter(Mandatory=$false)]
    [System.String]
    $PortalSiteAdministratorCredential,

    [Parameter(Mandatory=$false)]
    [System.String]
    $UseArcGISWebAdaptorForNotebookServer = 'true',

    [Parameter(Mandatory=$false)]
    [System.String]
    $DatabaseServerHostName, 

    [Parameter(Mandatory=$false)]
    [System.String]
    $DatabaseName, 

    [Parameter(Mandatory=$false)]
    [System.String]
    $DatabaseOption, 

    [Parameter(Mandatory=$false)]
    [System.String]
    $EnableGeodatabase = 'false', 

    [Parameter(Mandatory=$false)]
    [System.String]
    $RegisterEGDBAsRasterStore = 'false', 

    [Parameter(Mandatory=$false)]
    [System.String]
    $DatabaseServerAdministratorCredential,

    [Parameter(Mandatory=$false)]
    [System.String]
    $DatabaseUserCredential,

    [Parameter(Mandatory=$false)]
    [System.String]
    $CloudStores,

    [Parameter(Mandatory=$false)]
    [System.String]
    $CloudProvidedObjectStore,

    [Parameter(Mandatory=$false)]
    [System.String]
    $DataStoreTypes,

    [Parameter(Mandatory=$false)]
    [System.String]
    $IsDualMachineRelationalDataStore = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $IsMultiMachineGraphStore = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $IsMultiMachineSpatioTemporalDataStore = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $IsMultiMachineTileCacheDataStore = 'false',

    [Parameter(Mandatory=$false)]
    [System.String]
    $IsTileCacheDataStoreClustered = 'false',

    [parameter(Mandatory = $false)]
    [System.String]
    $GraphBackupLocation,
    
    [parameter(Mandatory = $false)]
    [System.String]
    $GraphBackupCredential,

    [parameter(Mandatory = $false)]
    [System.String]
    $PortalMachineNames,

    [parameter(Mandatory = $false)]
    [System.String]
    $PortalInternalCertificatePassword,

    [parameter(Mandatory = $false)]
    [System.String]
    $PortalAdministratorEmail,

    [parameter(Mandatory = $false)]
    [System.String]
    $PortalAdministratorSecurityQuestionCredential,

    [Parameter(Mandatory=$False)]
    [System.String]
    $PortalContext,

    [Parameter(Mandatory=$False)]
    [System.String]
    $PortalLicenseFileUrl,

    [Parameter(Mandatory=$False)]
    [System.String]
    $PortalLicenseUserTypeId,

    # Only for UninstallExtraSetups job
	[parameter(Mandatory = $false)]
    [System.String]
    $MachineRoles,

	[Parameter(Mandatory=$false)]
    [System.String]
    $DebugMode
)

$ErrorActionPreference = "Stop"
$DSCLogsFolder = "C:\ArcGIS\DSCLogs"

function Get-CredentialFromString {
    param(
        [Parameter(Mandatory=$False)]
        [System.String]
        $CredentialString,

        [Parameter(Mandatory=$False)]
        [System.String]
        $TranscriptPath
    )

    if (-not ([System.String]::IsNullOrEmpty($CredentialString))) {
        $UNArray = $CredentialString.Split(':')
        if ($UNArray.Count -ne 2) {
            # Improved error message for clarity
            throw "Invalid Credential String format. Input was '$CredentialString'. Please provide a valid credential string in the format 'base64(username):base64(password)'."
        }

        try {
            $CredUserName = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($UNArray[0]))
            $CredPassword = ConvertTo-SecureString -String ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($UNArray[1]))) -AsPlainText -Force

            # Create and return the PSCredential object
            return New-Object System.Management.Automation.PSCredential ($CredUserName, $CredPassword)
        }
        catch [System.FormatException] {
            # Catch errors specifically related to invalid Base64 input
            Write-Error ("Failed to decode Base64 string. Ensure both parts of '$CredentialString' are valid Base64 encoded strings. Error: $($_.Exception.Message)" | timestamp) *>&1 | Tee-Object -FilePath $TranscriptPath -Append 
            # Depending on requirements, you might return $null or re-throw
            throw $_ # Re-throw the original exception
        }
        catch {
            # Catch any other unexpected errors during the process
            Write-Error ("An unexpected error occurred while processing the credential string: $($_.Exception.Message)" | timestamp) *>&1 | Tee-Object -FilePath $TranscriptPath -Append 
            throw $_ # Re-throw the original exception
        }
    }
    return $null
}

$Debug = ($DebugMode -ieq 'true')
$TranscriptName = "DSCRunCommandLogs-$($ConfigurationName)-" + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')
$TranscriptPath = "$DSCLogsFolder\$($TranscriptName).txt"
if(-not(Test-Path $DSCLogsFolder)){
    New-Item -Path $DSCLogsFolder -ItemType "directory"
}
if($Debug){
    $DebugTranscriptPath = "$DSCLogsFolder\Debug-$($TranscriptName).txt"
    Start-Transcript -Path $DebugTranscriptPath -Append -IncludeInvocationHeader
}

Filter timestamp {
    $DateTimeUTC = [DateTime]::UtcNow.ToString((Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)
    if($_.GetType().Name -ieq "ErrorRecord" -or $_.GetType().Name -ieq "RemotingErrorRecord"){
        "[$($DateTimeUTC)]"; $_ 
    }else{
        "[$($DateTimeUTC)] $_"
    }
}

$ArcGISDSCLockFile = "C:\ArcGIS\ArcGISDSC.lock"

try{
    # check if the lock file exist and error out.
    if(Test-Path $ArcGISDSCLockFile){
        $start = Get-Date
        $DSCJobRunning = $true
        while ((Get-Date) - $start -lt [TimeSpan]::FromMinutes(60)) {
            $LCMState = (Get-DscLocalConfigurationManager).LCMState
            # We get the LCMState to check if the LCM is busy or not.
            # If the LCMState is not busy, we can remove the lock file and proceed with the DSC job.
            # If the LCMState is busy, we wait for 15 seconds and check again.
            # If the LCMState is still busy after 60 minutes, we error out.
            if($LCMState -ine "Busy"){
                try{
                    $ArcGISDSCLockFile | Remove-Item -Force
                    
                    Write-Information -InformationAction Continue ("Removing DSC Configuration Document" | timestamp) *>&1 | Tee-Object -FilePath $TranscriptPath -Append
                    Remove-DscConfigurationDocument -Stage Current,Pending,Previous -Force -ErrorAction Ignore

                    Write-Information -InformationAction Continue ("Removing DSC Configuration" | timestamp) *>&1 | Tee-Object -FilePath $TranscriptPath -Append
                    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }
                    
                    $DSCJobRunning = $false   
                    break
                } catch{ }
            }else{
                Write-Information -InformationAction Continue ("A DSC job is running. Waiting for some more time." | timestamp) *>&1 | Tee-Object -FilePath $TranscriptPath -Append
                Start-Sleep -Seconds 15
            }
        }

        if($DSCJobRunning){
            Write-error ("A DSC job is running. Please try again after sometime." | timestamp) -ErrorAction Continue *>&1 | Tee-Object -FilePath $TranscriptPath -Append
            exit 1
        }
    }    

    Write-Information -InformationAction Continue ("Staging ArcGIS DSC Module" | timestamp) *>&1 | Tee-Object -FilePath $TranscriptPath -Append 
    $DSCZipPath = (Join-Path $env:TEMP 'DSC.zip')
    Invoke-WebRequest -OutFile $DSCZipPath -Uri ([System.Net.WebUtility]::UrlDecode($DSCZipFileUrl))

    $PS_MODULE_STAGING_LOCATION = (Join-Path (Join-Path $env:Programfiles 'WindowsPowerShell') 'Modules')
    $DSC_MODULE_PATH = Join-Path $PS_MODULE_STAGING_LOCATION 'ArcGIS'
    if(Test-Path $DSC_MODULE_PATH){ Remove-Item $DSC_MODULE_PATH -Force -ErrorAction Ignore -Recurse }

    $ExpandLoc = (Join-Path $env:TEMP 'DSC')
    if(Test-Path $DSC_MODULE_PATH){ Remove-Item $ExpandLoc -Force -ErrorAction Ignore -Recurse }
    Expand-Archive -Path $DSCZipPath -DestinationPath $ExpandLoc -Force | Out-Null
    Remove-Item $DSCZipPath -Force -ErrorAction Ignore -Recurse 

    Copy-Item -Path (Join-Path $ExpandLoc 'ArcGIS') -Destination $PS_MODULE_STAGING_LOCATION -Recurse -Force
    Remove-Item $ExpandLoc -Force -ErrorAction Ignore -Recurse
    Write-Information -InformationAction Continue ("Staged ArcGIS DSC Module" | timestamp) *>&1 | Tee-Object -FilePath $TranscriptPath -Append

    $ArcGISServiceCredential = Get-CredentialFromString -CredentialString $ServiceCredential -TranscriptPath $TranscriptPath
    $MachineVMCredential = Get-CredentialFromString -CredentialString $MachineAdministratorCredential -TranscriptPath $TranscriptPath
    $SiteAdminCredential = Get-CredentialFromString -CredentialString $SiteAdministratorCredential -TranscriptPath $TranscriptPath

    $DSCArguments = @{
        'ConfigurationData' = @{
            AllNodes = @(
                @{
                    NodeName = "localhost"
                    PSDscAllowPlainTextPassword = $True
                }
            )
        }
    }

    $CurrentVersion = ($Version -split '@') | Select-Object -Last 1
    if($ConfigurationName -ieq "FileShareConfiguration"){
        $DSCArguments['ServiceCredential'] = $ArcGISServiceCredential
        $DSCArguments['ServiceCredentialIsDomainAccount'] = ($ServiceCredentialIsDomainAccount -ieq 'true')
        $DSCArguments['MachineAdministratorCredential'] = $MachineVMCredential
        $DSCArguments['ExternalDNSHostName'] = $ExternalDNSHostName
        $DSCArguments['FileShareName'] = $FileShareName
        
        if($IsBaseDeployment -ieq 'true'){
            $DSCArguments['IsBaseDeployment'] = $True
            $DSCArguments['PortalContext'] = $PortalContext
        }

        if($ServerRole -ieq "NotebookServer"){
            $DSCArguments['ServerContext'] = $ServerContext
            $DSCArguments['IsNotebookServerDeployment'] = $True
        }
        
        $DSCArguments['DebugMode'] = ($DebugMode -ieq 'true')
    }elseif($ConfigurationName -ieq "ServerConfiguration" -or $ConfigurationName -ieq "GISServerMultiTierConfiguration" -or $ConfigurationName -ieq "GISServerSingleTierConfiguration" -or $ConfigurationName -ieq "NotebookServerMultiTierConfiguration" -or $ConfigurationName -ieq "NotebookServerSingleTierConfiguration" -or $ConfigurationName -ieq "MissionServerMultiTierConfiguration" -or $ConfigurationName -ieq "MissionServerSingleTierConfiguration"){
        $DSCArguments['Version'] = $CurrentVersion
        $DSCArguments['DebugMode'] = ($DebugMode -ieq 'true')

        $DSCArguments['ServiceCredential'] = $ArcGISServiceCredential
        $DSCArguments['ServiceCredentialIsDomainAccount'] = ($ServiceCredentialIsDomainAccount -ieq 'true')
        
        if($ConfigurationName -ine "ServerConfiguration"){
            $DSCArguments['MachineAdministratorCredential'] = $MachineVMCredential
        }
        
        $DSCArguments['SiteAdministratorCredential'] = $SiteAdminCredential

        if($ConfigurationName -ieq "GISServerMultiTierConfiguration" -or $ConfigurationName -ieq "GISServerSingleTierConfiguration"){
            $DSCArguments['IsAddingServersOrRegisterEGDB'] = ($IsAddingServersOrRegisterEGDB -ieq 'true')
        }

        $DSCArguments['IsUpdatingCertificates'] = ($IsUpdatingCertificates -ieq 'true')
        $DSCArguments['ServerMachineNames'] = $ServerMachineNames
        $DSCArguments['ExternalDNSHostName'] = $ExternalDNSHostName
        
        if($ConfigurationName -ieq "ServerConfiguration"){
            $DSCArguments['ServerContext'] = $ServerContext
            $DSCArguments['IsAllInOneBaseDeploy'] = ($IsMultiTier -ieq 'false')
        }else{
            $DSCArguments['Context'] = $ServerContext
            $DSCArguments['PrivateDNSHostName'] = $PrivateDNSHostName    
        }

        if($ConfigurationName -ine "ServerConfiguration"){
            $DSCArguments['ServerRole'] = $ServerRole
            $DSCArguments['ServerFunctions'] = $ServerFunctions

            if($ConfigurationName -ieq "GISServerSingleTierConfiguration" -and $ServerRole -ieq "GeoeventServer"){
                $DSCArguments['GeoeventContext'] = $GeoeventContext
            }
        }
        
        $DSCArguments['UseExistingFileShare'] = ($UseExistingFileShare -ieq 'true')
        if($ConfigurationName -ine "ServerConfiguration"){
            $DSCArguments['UseFileShareMachineOfBaseDeployment'] = ($UseFileShareMachineOfBaseDeployment -ieq 'true')
        }
        $DSCArguments['FileShareMachineName'] = $FileShareMachineName
        $DSCArguments['FileShareName'] = $FileShareName
        $DSCArguments['FileSharePath'] = $FileSharePath

        $IsUsingCloudStorage = ($UseCloudStorage -ieq 'true')
        $DSCArguments['UseCloudStorage'] = $IsUsingCloudStorage
        if($IsUsingCloudStorage){
            $DSCArguments['UseAzureFiles'] = ($UseAzureFiles -ieq 'true')

            $DSCArguments['CloudStorageAuthenticationType'] = $CloudStorageAuthenticationType
            $DSCArguments['StorageAccountCredential'] = (Get-CredentialFromString -CredentialString $StorageAccountCredential -TranscriptPath $TranscriptPath)

            if($CloudStorageAuthenticationType -ieq 'ServicePrincipal'){
                $DSCArguments['StorageAccountServicePrincipalTenantId'] = $StorageAccountServicePrincipalTenantId
                $DSCArguments['StorageAccountServicePrincipalAuthorityHost'] = $StorageAccountServicePrincipalAuthorityHost
                $DSCArguments['StorageAccountServicePrincipalCredential'] = (Get-CredentialFromString -CredentialString $StorageAccountServicePrincipalCredential -TranscriptPath $TranscriptPath)
            }elseif($CloudStorageAuthenticationType -ieq 'UserAssignedIdentity'){
                $DSCArguments['StorageAccountUserAssignedIdentityClientId'] = $StorageAccountUserAssignedIdentityClientId
            }
        }
        
        $DSCArguments['ServerLicenseFileUrl'] = $ServerLicenseFileUrl
        $DSCArguments['PublicKeySSLCertificateFileUrl'] = $PublicKeySSLCertificateFileUrl
        
        if(-not([System.String]::IsNullOrEmpty($ServerInternalCertificatePassword))){
            $ServerInternalCertificatePass = ConvertTo-SecureString -String $ServerInternalCertificatePassword -AsPlainText -Force
            $ServerInternalCertificatePasswordCred = New-Object System.Management.Automation.PSCredential ("placeholder", $ServerInternalCertificatePass)
            $DSCArguments['ServerInternalCertificatePassword'] = $ServerInternalCertificatePasswordCred
        }

        if($ConfigurationName -ine "ServerConfiguration"){
            $IsFederatedSite = ($FederateSite -ieq 'true')
            if ($IsFederatedSite) {
                $DSCArguments['FederateSite'] = $True
                $DSCArguments['PortalContext'] = $PortalContext

                $DSCArguments['PortalMachineNamesOnHostingServer'] = $PortalMachineNamesOnHostingServer
                $DSCArguments['GisServerMachineNamesOnHostingServer'] = $GisServerMachineNamesOnHostingServer
                $DSCArguments['PortalSiteAdministratorCredential'] = (Get-CredentialFromString -CredentialString $PortalSiteAdministratorCredential -TranscriptPath $TranscriptPath)
                
                # Notebook Server
                if($ServerRole -ieq "NotebookServer"){
                    $DSCArguments['UseArcGISWebAdaptorForNotebookServer'] = ($UseArcGISWebAdaptorForNotebookServer -ieq 'true')
                }
            }
        }

        if(-not([string]::IsNullOrEmpty($DatabaseServerHostName))){
            $DSCArguments['DatabaseServerHostName'] = $DatabaseServerHostName
            $DSCArguments['DatabaseName'] = $DatabaseName
            $DSCArguments['DatabaseOption'] = $DatabaseOption
            $DSCArguments['EnableGeodatabase'] = ($EnableGeodatabase -ieq 'true')
            $DSCArguments['DatabaseServerAdministratorCredential'] = (Get-CredentialFromString -CredentialString $DatabaseServerAdministratorCredential -TranscriptPath $TranscriptPath)
            $DSCArguments['DatabaseUserCredential'] = (Get-CredentialFromString -CredentialString $DatabaseUserCredential -TranscriptPath $TranscriptPath)
            if($ConfigurationName -ieq "GISServerMultiTierConfiguration" -or $ConfigurationName -ieq "GISServerSingleTierConfiguration"){
                $DSCArguments['RegisterEGDBAsRasterStore'] = ($RegisterEGDBAsRasterStore -ieq 'true')
            }
        }

        if($ConfigurationName -ieq "ServerConfiguration" -or $ConfigurationName -ieq "GISServerMultiTierConfiguration" -or $ConfigurationName -ieq "GISServerSingleTierConfiguration"){
            $DSCArguments['EnableLogHarvesterPlugin'] = ($EnableLogHarvesterPlugin -ieq 'true')
            if(-not([System.String]::IsNullOrEmpty($CloudStores))){
                $DSCArguments['CloudStores'] = (ConvertFrom-Json $CloudStores)
            }
        }

        if($ConfigurationName -ieq "ServerConfiguration"){ 
            if(-not([System.String]::IsNullOrEmpty($CloudProvidedObjectStore)) -and ($CloudProvidedObjectStore -ine '{}')){
                $CloudObjectStore = (ConvertFrom-Json $CloudProvidedObjectStore)
                $DSCArguments['CloudProvidedObjectStore'] = @($CloudObjectStore)
            }
        }

    }elseif($ConfigurationName -ieq "PortalConfiguration"){
        $DSCArguments['Version'] = $CurrentVersion
        $DSCArguments['DebugMode'] = ($DebugMode -ieq 'true')
        $DSCArguments['ServiceCredential'] = $ArcGISServiceCredential
        $DSCArguments['ServiceCredentialIsDomainAccount'] = ($ServiceCredentialIsDomainAccount -ieq 'true')
        $DSCArguments['SiteAdministratorCredential'] = $SiteAdminCredential
        $DSCArguments['ServerMachineNames'] = $ServerMachineNames
        $DSCArguments['PortalMachineNames'] = $PortalMachineNames
        $DSCArguments['IsUpdatingCertificates'] = ($IsUpdatingCertificates -ieq 'true')
        $DSCArguments['IsAllInOneBaseDeploy'] = ($IsMultiTier -ieq 'false')
        if(-not([System.String]::IsNullOrEmpty($PortalAdministratorSecurityQuestionCredential))){
            $DSCArguments['PortalAdministratorSecurityQuestionCredential'] = (Get-CredentialFromString -CredentialString $PortalAdministratorSecurityQuestionCredential -TranscriptPath $TranscriptPath)
        }

        if(-not([System.String]::IsNullOrEmpty($PortalAdministratorEmail))){
            $DSCArguments['PortalAdministratorEmail'] = $PortalAdministratorEmail
        }

        $DSCArguments['ServerContext'] = $ServerContext
        $DSCArguments['PortalContext'] = $PortalContext
        $DSCArguments['ExternalDNSHostName'] = $ExternalDNSHostName
        $DSCArguments['PrivateDNSHostName'] = $PrivateDNSHostName
        
        $DSCArguments['PortalLicenseFileUrl'] = $PortalLicenseFileUrl
        $DSCArguments['PortalLicenseUserTypeId'] = $PortalLicenseUserTypeId
        
        $DSCArguments['PublicKeySSLCertificateFileUrl'] = $PublicKeySSLCertificateFileUrl
        if(-not([System.String]::IsNullOrEmpty($PortalInternalCertificatePassword))){
            $PortalInternalCertificatePass = ConvertTo-SecureString -String $PortalInternalCertificatePassword -AsPlainText -Force
            $PortalInternalCertificatePasswordCred = New-Object System.Management.Automation.PSCredential ("placeholder", $PortalInternalCertificatePass)
            $DSCArguments['PortalInternalCertificatePassword'] = $PortalInternalCertificatePasswordCred
        }
        
        $DSCArguments['UseExistingFileShare'] = ($UseExistingFileShare -ieq 'true')
        $DSCArguments['FileShareMachineName'] = $FileShareMachineName
        $DSCArguments['FileShareName'] = $FileShareName
        $DSCArguments['FileSharePath'] = $FileSharePath

        $IsUsingCloudStorage = ($UseCloudStorage -ieq 'true')
        $DSCArguments['UseCloudStorage'] = $IsUsingCloudStorage
        if($IsUsingCloudStorage){
            $DSCArguments['UseAzureFiles'] = ($UseAzureFiles -ieq 'true')
            $DSCArguments['CloudStorageAuthenticationType'] = $CloudStorageAuthenticationType
            $DSCArguments['StorageAccountCredential'] = (Get-CredentialFromString -CredentialString $StorageAccountCredential -TranscriptPath $TranscriptPath)

            if($CloudStorageAuthenticationType -ieq 'ServicePrincipal'){
                $DSCArguments['StorageAccountServicePrincipalTenantId'] = $StorageAccountServicePrincipalTenantId
                $DSCArguments['StorageAccountServicePrincipalAuthorityHost'] = $StorageAccountServicePrincipalAuthorityHost
                $DSCArguments['StorageAccountServicePrincipalCredential'] = (Get-CredentialFromString -CredentialString $StorageAccountServicePrincipalCredential -TranscriptPath $TranscriptPath)
            }elseif($CloudStorageAuthenticationType -ieq 'UserAssignedIdentity'){
                $DSCArguments['StorageAccountUserAssignedIdentityClientId'] = $StorageAccountUserAssignedIdentityClientId
            }
        }
    }elseif($ConfigurationName -ieq "DataStoreConfiguration"){
        $DSCArguments['Version'] = $CurrentVersion
        $DSCArguments['DebugMode'] = ($DebugMode -ieq 'true')
        $DSCArguments['ServiceCredential'] = $ArcGISServiceCredential
        $DSCArguments['ServiceCredentialIsDomainAccount'] = ($ServiceCredentialIsDomainAccount -ieq 'true')
        $DSCArguments['SiteAdministratorCredential'] = $SiteAdminCredential
        $DSCArguments['ServerMachineNames'] = $ServerMachineNames
        $DSCArguments['IsAllInOneBaseDeploy'] = ($IsMultiTier -ieq 'false')

        $DSTypesArray = ($DataStoreTypes -split ',')
        $DSCArguments['DataStoreTypes'] = $DSTypesArray
        
        if($DSTypesArray -icontains "Relational"){
            $DSCArguments['IsDualMachineRelationalDataStore'] = ($IsDualMachineRelationalDataStore -ieq 'true')
        }

        if($DSTypesArray -icontains "SpatioTemporal"){
            $DSCArguments['IsMultiMachineSpatioTemporalDataStore'] = ($IsMultiMachineSpatioTemporalDataStore -ieq 'true')
        }

        if($DSTypesArray -icontains "TileCache"){
            $DSCArguments['IsMultiMachineTileCacheDataStore'] = ($IsMultiMachineTileCacheDataStore -ieq 'true')
            $DSCArguments['IsTileCacheDataStoreClustered'] = ($IsTileCacheDataStoreClustered -ieq 'true')
        }
        
        if($DSTypesArray -icontains "GraphStore"){
            $DSCArguments['IsMultiMachineGraphStore'] = ($IsMultiMachineGraphStore -ieq 'true')
        }
    }elseif($ConfigurationName -ieq "GraphStoreBackupConfiguration"){
        $DSCArguments['Version'] = $CurrentVersion
        if(-not([System.String]::IsNullOrEmpty($GraphBackupLocation))){
            $DSCArguments['GraphBackupCredential'] = (Get-CredentialFromString -CredentialString $GraphBackupCredential -TranscriptPath $TranscriptPath)
            $DSCArguments['GraphBackupLocation'] = $GraphBackupLocation
        }
    }elseif($ConfigurationName -ieq "UninstallExtraSetups"){
        $DSCArguments['Version'] = $CurrentVersion
        $DSCArguments['MachineRoles'] = $MachineRoles
        $DSCArguments['ServerRole'] = $ServerRole
        $DSCArguments['DebugMode'] = ($DebugMode -ieq 'true')
    }elseif($ConfigurationName -ieq "SQLServerConfiguration"){
        $DSCArguments['DatabaseAdminCredential'] = (Get-CredentialFromString -CredentialString $DatabaseServerAdministratorCredential -TranscriptPath $TranscriptPath)
    }else{
        throw "Invalid Configuration Name"
    }
        
    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }
    Write-Information -InformationAction Continue ("Dot Sourcing the Configuration:- $ConfigurationName" | timestamp) *>&1 | Tee-Object -FilePath $TranscriptPath -Append
    . "$DSC_MODULE_PATH\Configurations-Azure\$($ConfigurationName).ps1" -Verbose:$false
    &$ConfigurationName @DSCArguments -Verbose

    Write-Information -InformationAction Continue ("Starting DSC Job for Configuration:- $ConfigurationName" | timestamp) *>&1 | Tee-Object -FilePath $TranscriptPath -Append
    $JobTimer = [System.Diagnostics.Stopwatch]::StartNew()
    if(-not(Test-Path $DSCLogsFolder)){ New-Item -Path $DSCLogsFolder -ItemType "directory" }
    $DSCJob = Start-DscConfiguration -Path ".\$($ConfigurationName)" -ComputerName 'localhost' -Verbose -Force
    # Add a lock file 
    New-Item -ItemType "file" $ArcGISDSCLockFile

    $timestamp = (($DSCJob.PSBeginTime).toString()).Replace(':','-').Replace('/','-').Replace(' ','-')
    $DSCJob | Receive-Job -Verbose -Wait *>&1 | timestamp *>&1 | Tee-Object -FilePath $TranscriptPath -Append
    if($DSCJob.state -ine "Completed"){
        throw "DSC Job failed to complete. Please check the logs for more details."
    }

    Write-Information -InformationAction Continue ("Finished DSC Job:- $ConfigurationName. Time Taken - $($JobTimer.elapsed)"| timestamp) *>&1 | Tee-Object -FilePath $TranscriptPath -Append

    if(Test-Path $ArcGISDSCLockFile){
        # Remove the lock file
        $ArcGISDSCLockFile | Remove-Item -Force
    }

    Remove-DscConfigurationDocument -Stage Current -Force -ErrorAction Ignore
    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }
    if($Debug){
        Stop-Transcript
    }
} catch {
    if(Test-Path $ArcGISDSCLockFile){
        # Remove the lock file
	    $ArcGISDSCLockFile | Remove-Item -Force
    }
    # Write the error to the console and exit with error code 1
    Remove-DscConfigurationDocument -Stage Current -Force -ErrorAction Ignore
    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }
    Write-Error $_  -ErrorAction Continue *>&1 | Tee-Object -FilePath $TranscriptPath -Append 
    if($Debug){
        Stop-Transcript
    }
    exit 1
}