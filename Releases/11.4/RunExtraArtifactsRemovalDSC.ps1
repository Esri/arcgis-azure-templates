param(
    [string]
    $DSCZipFileUrl,

    [Parameter(Mandatory=$false)]
    [System.String]
    $Version = '11.4',

	[parameter(Mandatory = $false)]
    [System.String]
    $MachineRoles,
		
	[parameter(Mandatory = $False)]
	[System.String]
    $ServerRole,

	[Parameter(Mandatory=$false)]
    [System.Boolean]
    $DebugMode
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Filter timestamp {
    $DateTimeUTC = [DateTime]::UtcNow.ToString((Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)
    if($_.GetType().Name -ieq "ErrorRecord" -or $_.GetType().Name -ieq "RemotingErrorRecord"){
        "[$($DateTimeUTC)]"; $_
    }else{
        "[$($DateTimeUTC)] $_"
    }
}

$ConfigurationName = 'UninstallExtraSetups'
$LockFile = "C:\ArcGIS\RunCMDLogs.lock"

try {

	# check if the lock file exist and error out.
    if(Test-Path $LockFile){
        $start = Get-Date
        $DSCJobRunning = $true
        while ((Get-Date) - $start -lt [TimeSpan]::FromMinutes(120)) {
            $LCMState = (Get-DscLocalConfigurationManager).LCMState
            if($LCMState -ine "Busy"){
                try{
                    $LockFile | Remove-Item -Force
                    Remove-DscConfigurationDocument -Stage Current -Force -ErrorAction Ignore
                    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }
                    $DSCJobRunning = $false   
                    break
                } catch{ }
            }else{
                Write-Information -InformationAction Continue ("A DSC Job is running. Waiting for some more time." | timestamp)
                Start-Sleep -Seconds 15
            }
        }

        if($DSCJobRunning){
            Write-error ("A DSC Job is running. Please try again after sometime." | timestamp)
            exit 1
        }
    }

    Write-Information -InformationAction Continue "Staging ArcGIS DSC Module"
    $DSCZipPath = (Join-Path $env:TEMP 'DSC.zip')
    Invoke-WebRequest -OutFile $DSCZipPath -Uri ([System.Net.WebUtility]::UrlDecode($DSCZipFileUrl))

    $PS_MODULE_STAGING_LOCATION = Join-Path $env:Programfiles 'WindowsPowerShell\\Modules'
    $DSC_MODULE_PATH = Join-Path $PS_MODULE_STAGING_LOCATION 'ArcGIS'
    if(Test-Path $DSC_MODULE_PATH){ Remove-Item $DSC_MODULE_PATH -Force -ErrorAction Ignore -Recurse }

    $ExpandLoc = (Join-Path $env:TEMP 'DSC')
    if(Test-Path $DSC_MODULE_PATH){ Remove-Item $ExpandLoc -Force -ErrorAction Ignore -Recurse }
    Expand-Archive -Path $DSCZipPath -DestinationPath $ExpandLoc -Force | Out-Null
    Remove-Item $DSCZipPath -Force -ErrorAction Ignore -Recurse 

    Copy-Item -Path (Join-Path $ExpandLoc 'ArcGIS') -Destination $PS_MODULE_STAGING_LOCATION -Recurse -Force
    Remove-Item -Path (Join-Path $ExpandLoc 'ArcGIS') -Recurse
    New-Item (Join-Path $PS_MODULE_STAGING_LOCATION "ArcGIS\Configurations-Azure") -ItemType Directory
    Copy-Item "$ExpandLoc\*" (Join-Path $PS_MODULE_STAGING_LOCATION "ArcGIS\Configurations-Azure") -Recurse
    Remove-Item $ExpandLoc -Force -ErrorAction Ignore -Recurse
    Write-Information -InformationAction Continue "Staged ArcGIS DSC Module"

    $Arguments = @{
        'ConfigurationData' = @{
                AllNodes = @(
                    @{
                        NodeName = "localhost"
                    }
                )
            }
	    'Version' = $Version
	    'MachineRoles' = $MachineRoles
        'ServerRole' = $ServerRole
	    'DebugMode' = $DebugMode
    }

    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }
    Write-Information -InformationAction Continue ("Dot Sourcing the Configuration:- $ConfigurationName" | timestamp)
    . "$DSC_MODULE_PATH\Configurations-Azure\$($ConfigurationName).ps1" -Verbose:$false
    &$ConfigurationName @Arguments -Verbose

    Write-Information -InformationAction Continue ("Starting DSC Job for Configuration:- $ConfigurationName" | timestamp)
    $JobTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $DSCLogsFolder = "C:\ArcGIS\RunCMDLogs"
    if(-not(Test-Path $DSCLogsFolder)){ New-Item -Path $DSCLogsFolder -ItemType "directory" }
    $job = Start-DscConfiguration -Path ".\$($ConfigurationName)" -ComputerName 'localhost' -Verbose -Force
    # Add a lock file 
    New-Item -ItemType "file" $LockFile 

    $timestamp = (($job.PSBeginTime).toString()).Replace(':','-').Replace('/','-').Replace(' ','-')
    $job | Receive-Job -Verbose -Wait *>&1 | timestamp | Tee-Object -FilePath "$($DSCLogsFolder)\$($ConfigurationName)-$($timestamp).txt"
    if($Job.state -ine "Completed"){
        throw "DSC Job failed to complete. Please check the logs for more details."
    }

    Write-Information -InformationAction Continue ("Finished DSC Job:- $ConfigurationName. Time Taken - $($JobTimer.elapsed)"| timestamp)

    if(Test-Path $LockFile){
        # Remove the lock file
	    $LockFile | Remove-Item -Force
    }

    Remove-DscConfigurationDocument -Stage Current -Force -ErrorAction Ignore
    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }
}
catch {
    if(Test-Path $LockFile){
        # Remove the lock file
	    $LockFile | Remove-Item -Force
    }
    # Write the error to the console and exit with error code 1
    Remove-DscConfigurationDocument -Stage Current -Force -ErrorAction Ignore
    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }
    Write-Error $_
    exit 1
}