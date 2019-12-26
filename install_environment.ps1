<#
.SYNOPSIS
    This is an automated generic script to help install some parts of a developer environment.

.PARAMETER envPrefix
    Used as environment name. Maximum number of characters for environment name is max(N).

.PARAMETER pathToStoreRepoSources
    Used as path to workspace, where repository source code will be downloaded. 
    Provide path, for example C:\Path or F:\Path or any other path.

.PARAMETER pathToSQLInstaller
    Path to SQL Server ISO.

.EXAMPLE
    PS > ./Install_Development_Environment.ps1
    Install development environment using default parameters. To view default parameters run the following cmdlet: 
    Get-Help .\PathTo\Install_Development_Environment.ps1 -Full

.EXAMPLE
    PS > ./Install_Development_Environment.ps1 -envPrefix <EnvironmentName> -pathToStoreRepoSources <PathToStoreSources> -pathToSQLInstaller <SQLInstallerPath>
    Install development environment using the custom parameters.

.DESCRIPTION
    If you want to install environment manually then please refer to the RELATED LINKS section or run the following cmdlet:
    Get-Help .\PathTo\Install_Development_Environment.ps1 -Online

.LINK
    https://lmgtfy.com/?q=how+to+use+powershell&s=b
#>

[CmdletBinding()]
Param(
    [String]$envPrefix = "dev",

    [String]$pathToStoreRepoSources = "C:\",

    [String]$pathToSQLInstaller = "$env:USERPROFILE\Downloads"
)

###############################################################
## Variables which will be used during installing environment.
###############################################################
$sourceGitRepository = "https://github.com/"

$srcDirName = $pathToStoreRepoSources

# SQL server variables
$sqlServerName = $env:computername
$sqlServerInstanceName = "MSSQLSERVER"
$sqlVersion = 13
$sqlVersionNumber = 130

# Registry keys
$dataCenterPublisherName = "DataCenterPublisherName"
$databasePublisherName = "DatabasePublisherName"

# Databases names
$companyDBName = $envPrefix + "_Company"

$Databases = @($companyDBName)

# Databases user names
$companyUser = $envPrefix + "_Company"

$DBUsers = @($companyUser)

#####################################################################################################
## Calls the main routine to install environment. This function is called by last line in this file.
#####################################################################################################
function Install-Environment {
    
    try {
        Approve-ThisIsDevMachine
        Approve-ScriptParameters

        if ((Assert-SourcesCorrect) -eq "Failed") {
            Get-Sources
            if ((Assert-SourcesCorrect) -eq "Failed") {
                Write-Host -foreground Red "[ERROR]: Source code couldn't be not verified!"
                throw "ERROR"
            }
        }

        Initialize-WindowsOptionalFeatures

        if ((Assert-SQLServerConfiguration) -eq "Failed") {
            Install-SQLServer
            if ((Assert-SQLServerConfiguration) -eq "Failed") {
                Write-Host -foreground Red "[ERROR]: SQL Server Configuration was not verified!"
                throw "ERROR"
            }
        }

        if ((Assert-QueuesInstalled) -eq "Failed") {
            $installationOfQueuesResult = Install-Queues
            if (($installationOfQueuesResult -ne 0) -and (Assert-QueuesInstalled) -eq "Failed") {
                Write-Host -foreground Red "[ERROR]: Queues are not configured!"
                throw "ERROR"                
            }
        }

        if ((Assert-WebAppResponds) -eq "Failed") {
            Set-IIS
            if ((Assert-WebAppResponds) -eq "Failed") {
                Write-Host -foreground Red "[ERROR]: WebApp doesn't respond properly!"
                throw "ERROR"
            }            
        }

        Write-Host -foreground Green "Dev environment successfully installed. You can find it here: https://localhost/${envPrefix}/`n"
    } catch {
        Write-Host -foreground Red "[ERROR]: Dev environment installation failed. Some errors occured!`n"
    }
}

function Approve-ThisIsDevMachine {
    Write-Warning "This script assumes that you have .NET environment set up already."
    Write-Host -ForegroundColor Cyan "For more information about installation run the command: Get-Help ./Install_Development_Environment.ps1 -Online"
    $confirmation = Read-Host "Do you want to run the script? (y/n)"
    if ($confirmation -ne "y") {
        Write-Warning "Exiting installation. Good bye!`n"
        exit
    }
}

function Approve-ScriptParameters {
    $confirmation = Read-Host "`nProceed installation with the following parameters: `
    envPrefix: $envPrefix `
    installationPath: $pathToStoreRepoSources `
    pathToSQLInstaller: $env:USERPROFILE\Downloads`n(y/n)"
    
    if ($confirmation -ne "y") {
        Write-Warning "Sorry, can't proceed with installation. Relaunch script with desired parameters.`n"
        Write-Host -ForegroundColor Cyan "Example: ./Install_Development_Environment.ps1 -envPrefix <EnvironmentName> -pathToStoreRepoSources <DriveToStoreSources> -pathToSQLInstaller <SQLInstallerPath>"
        Write-Host -ForegroundColor Cyan "For more information about script run command: Get-Help ./Install_Development_Environment.ps1 -Full"
        exit
    }
}

################################################
## Checks that source code is on local machine.
################################################
function Assert-SourcesCorrect {
    Write-Host "`n[STEP]: Verifying if source code is present on machine and if it is in sync with remote..."

    if ((Test-Path -Path "$srcDirName")) {
        Set-Location -Path "$srcDirName"

        [string]$GitRepoState = git checkout -f HEAD 2>&1
        if ($GitRepoState -like "*fatal: not a git repository*") {
            Write-Warning $GitRepoState
            $confirmation = Read-Host "Do you want me to download source code? (y/n)"
            if ($confirmation -eq "y") {
                Get-Sources
            } else {
                Write-Warning "Please resolve problems with source code directory.`n"
                exit
            }            
        } elseif ($GitRepoState -like "fatal: destination path ${srcDirName} already exists and is not an empty directory.*") {
            Write-Warning $repoState
            return "Failed"
        } elseif ($GitRepoState -like "*Your branch is behind*") {
            git fetch -f | Write-Host
            git prune -v | Write-Host
            git pull  -f | Write-Host
        }
        Write-Host -foreground Green "Source code verified.`n"
        return "Passed"        
    } else {
        Write-Warning "Source code is not available.`n"
        return "Failed"
    }
}

#################################################
## Downloads source code from remote repository.
#################################################
function Get-Sources {
    Write-Host "[STEP]: Source code will be downloaded and git will be configured to work with repo..."
    Set-Location -Path $pathToStoreRepoSources

    $loginName = Read-Host "Please provide your login:"
    cmdkey /generic:git:$sourceGitRepository /user:$loginName /pass
    git config --system credential.helper wincred
    git config --global credential.helper wincred
    git clone --verbose $sourceGitRepository

    if ((Test-Path $srcDirName)) {
        Set-Location -Path $srcDirName
        $name = Read-Host "Please provide your name: (ex.: John Anonymous)"
        git config user.name $name
        $email = Read-Host "Please provide your email: (ex.: name.surname@mail.com)"
        git config user.email $email
        Write-Host -foreground Green "Source code was downloaded and git was configured to work with repo."
    } else {
        Write-Host -ForegroundColor Red "It seems that source code is missing! Maybe Network issue happened during source code download."
        throw "ERROR"
    }
}

#################################################
## Enables necessary Windows features for setup.
#################################################
function Initialize-WindowsOptionalFeatures {
    Write-Host "[STEP]: Setting Windows Optional Features..."

    $listOfWindowsFeatures = @("IIS-WebServerRole", "IIS-WebServer", "IIS-ManagementConsole", "IIS-ManagementScriptingTools", "IIS-ManagementService", 
                               "IIS-NetFxExtensibility", "IIS-NetFxExtensibility45", "IIS-ApplicationInit", "IIS-ASP", "IIS-ASPNET", "IIS-ASPNET45", 
                               "IIS-ISAPIExtensions", "IIS-ISAPIFilter", "IIS-WebSockets", "IIS-CommonHttpFeatures", "IIS-HealthAndDiagnostics", 
                               "IIS-Performance", "IIS-Security", "MSMQ-ADIntegration", "MSMQ-Triggers", "MSMQ-Multicast", "MSMQ-DCOMProxy")

    foreach ($windowsFeature in $listOfWindowsFeatures) {
        Write-Host "Checking $windowsFeature status:"
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $windowsFeature
        if ($feature.State -eq "Disabled") {
            Write-Verbose "Feature $windowsFeature is disabled. Enabling feature..."
            Enable-WindowsOptionalFeature -Online -FeatureName $windowsFeature -All
        } else {
            Write-Host -foreground Green $feature.State
        }
    }

    Write-Host -foreground Green "Finished setting Windows Optional Features.`n"
}

##################################################
## Installs SQL Server with necessary parameters.
##################################################
function Install-SQLServer {
    Write-Host "[STEP]: Installing SQL Server..."

    $sqlImage = Get-Childitem -Path $pathToSQLInstaller -Include "*ISO*" -File -Recurse -ErrorAction SilentlyContinue
    $configFile = "${pathToSQLInstaller}\ConfigurationFile.ini"    
    
    $isoVolume = Mount-DiskImage $sqlImage.FullName -PassThru | Get-Volume
    $driveLetter = $isoVolume.DriveLetter
    Enable-ComputerRestore -Drive "C:\"

    $sqlInstallationError = $false

    Write-Host "SQL Server installation will take some time. Please wait...`n"
    try {
        $pass = Read-Host "Please enter SA Password (Password Complexity should be strong)" -AsSecureString
        Start-Process "${driveLetter}:\setup.exe" -ArgumentList "/ConfigurationFile=$configFile", "/SAPWD='$pass'" -Wait -NoNewWindow
    } catch {
        Write-Warning "Error occured during SQL Server installation!`n"
        $sqlInstallationError = $true
    } finally {
        Dismount-DiskImage -ImagePath $sqlImage.FullName
        if ($sqlInstallationError) {
            throw "ERROR"
        }
    }

    if(-not (Get-Module "sqlps")) {
        $env:PSModulePath = $env:PSModulePath + ";C:\Program Files (x86)\Microsoft SQL Server\$sqlVersionNumber\Tools\PowerShell\Modules"
        Import-Module sqlps
    }

    $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer")
    $uri = "ManagedComputer[@Name='${sqlServerName}']/ServerInstance[@Name='${sqlServerInstanceName}']/ServerProtocol[@Name='Tcp']"
    $Tcp = $wmi.GetSmoObject($uri)
    $Tcp.IsEnabled = $true
    $Tcp.Alter()
    $Tcp

    Restart-Service -Force MSSQLSERVER
    Write-Host -foreground Green "Finished installing SQL Server.`n"
}

##################################################
## Checks that SQL Server is installed correctly.
##################################################
function Assert-SQLServerConfiguration {
    Write-Host "[STEP]: Verifying SQL Server installation..."

    if ((Test-Path -Path "C:\Program Files\Microsoft SQL Server\MSSQL$sqlVersion.MSSQLSERVER\MSSQL\Binn\sqlservr.exe")) {
        try {
            Restart-Service -Force MSSQLSERVER
        } catch {
            Write-Warning "SQL Server is not found!`n"
            return "Failed"
        }
    } else {
        Write-Warning "SQL Server is not found!`n"
        return "Failed"
    }

    if(-not (Get-Module "sqlps")) {
        $env:PSModulePath = $env:PSModulePath + ";C:\Program Files (x86)\Microsoft SQL Server\$sqlVersionNumber\Tools\PowerShell\Modules"
        Import-Module sqlps
    }

    Write-Host "Verifying that SQL Server collation is set to SQL_Latin1_General_CP1_CI_AS..."
    $queryResult = Invoke-Sqlcmd -Query "select serverproperty('collation') as Collation" -ServerInstance .
    if ($queryResult.Collation -ne "SQL_Latin1_General_CP1_CI_AS") {
        Write-Warning "SQL collation is not SQL_Latin1_General_CP1_CI_AS! SQL Server reinstall is necessary."
        if ((Show-SQLServerReinstallConfirmation) -eq "Failed") {
            return "Failed"
        } 
    } else {
        Write-Host -foreground Green "SQL Server Collation is SQL_Latin1_General_CP1_CI_AS."
    }

    Write-Host "Verifying that SQL Server is set to default instance..."
    $sqlServerInstance = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server").InstalledInstances
    if ($sqlServerInstance -ne $sqlServerInstanceName) {
        Write-Warning "Check that SQLServer is set to Default Instance!"
        if ((Show-SQLServerReinstallConfirmation) -eq "Failed") {
            return "Failed"
        }
    } else {
        Write-Host -foreground Green "SQL Server is set to Default Instance."
    }

    Write-Host "Verifying that SQL Server Analysis Services is enabled..."
    $SSAS = Get-RegistryKeyContent "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSAS${sqlVersion}.MSSQLSERVER\MSSQLServer\CurrentVersion" CurrentVersion
    if (!$SSAS.Contains($sqlVersion)) {
        Write-Host "Analysis services should be installed!`n"
        if ((Show-SQLServerReinstallConfirmation) -eq "Failed") {
            return "Failed"
        }
    } else {
        Write-Host -foreground Green "SQL Server Analysis Services is enabled."
    }

    Write-Host "Verifying that SQL Server Integration Services enabled..."
    $SSIS = Get-RegistryKeyContent "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$sqlVersionNumber\DTS\Setup" Version
    if (!$SSIS.Contains($sqlVersion)) {
        Write-Host "Integration services should be installed!"
        if ((Show-SQLServerReinstallConfirmation) -eq "Failed") {
            return "Failed"
        }
    } else {
        Write-Host -foreground Green "Integration services are installed."
    }

    Write-Host "Verifying that Analysis Services are in Multi-dimensional mode..."
    $deploymentMode = Select-Xml -Path "C:\Program Files\Microsoft SQL Server\MSAS13.MSSQLSERVER\OLAP\Config\msmdsrv.ini" -XPath "//DeploymentMode"
    if ($deploymentMode.Node."#text" -ne 0) {
        Write-Host "Analysis services should be installed in Multi-dimensional mode."
        if ((Show-SQLServerReinstallConfirmation) -eq "Failed") {
            return "Failed"
        }
    } else {
        Write-Host -foreground Green "SQL Server Analysis Services are in Multi-dimensional mode."
    }

    Write-Host "Verifying that SQL Server authentication is in mixed mode..."
    $sqlServerAuthMode = Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLSERVER"
    if ($sqlServerAuthMode.LoginMode -ne 2) {
        Write-Warning "SQL Server authentication should be SQL Server and Windows Authentication mode".
        Write-Verbose "Setting authentication mode to mixed"
        Set-Itemproperty -path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL$sqlVersion.MSSQLSERVER\MSSQLServer" -Name "LoginMode" -value "2"
        Restart-Service -Force MSSQLSERVER
    } else {
        Write-Host -foreground Green "SQL Server authentication is in mixed mode."
    }
    
    Write-Host "Verifying that SQL Server TCP/IP Protocol is enabled..."
    $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer")
    $uri = "ManagedComputer[@Name='$sqlServerName']/ServerInstance[@Name='${sqlServerInstanceName}']/ServerProtocol[@Name='Tcp']"
    $Tcp = $wmi.GetSmoObject($uri)
    if($Tcp.IsEnabled -ne $true) {
        Write-Warning "Protocol TCP/IP for $sqlServerInstanceName should be enabled"
        $Tcp.IsEnabled = $true
        $Tcp.Alter()
        $sqlServerService = Get-Service MSSQLSERVER
        Restart-Service -Force MSSQLSERVER
        $sqlServerService.WaitForStatus('Started', '00:00:05')
        if ($Tcp.IsEnabled -ne $true) {
            return "Failed"
        }
    } else {
        Write-Host -foreground Green "SQL Server TCP/IP Protocol is enabled."
    }

    Write-Host -foreground Green "SQL Server installation - Verified`n"
    return "Passed"
}

###################################################################################
## Function Helper for Assert-SQLServerConfiguration to get registry value by key.
###################################################################################
function Get-RegistryKeyContent($key, $value) { 
    (Get-ItemProperty -Path $key $value -ErrorAction SilentlyContinue).$value
}

################################################################
## Function Helper to ask confirmation to reinstall SQL Server.
################################################################
function Show-SQLServerReinstallConfirmation {
    $confirmation = Read-Host "Automatically reinstall SQL Server?"
    if ($confirmation -eq "y") {
        Install-SQLServer
        return "Passed"
    } else {
        Write-Warning "Please, reinstall SQL Server manually.`n"
        return "Failed"
    }
}

############################################################
## Gets Microsoft Build executable path (VS2015/2017/2019).
############################################################
function Get-MSBuildPath {
    # We will use wildcard in the path so it matches Enterprise, Community or Professional version.

    # Path for MSBuild 2017 - Assume it exists, because this version is widely used among developers.
    $paths = @(Resolve-Path "C:\Program Files (x86)\Microsoft Visual Studio\2017\*\MSBuild\15.0\Bin\MsBuild.exe" -ErrorAction Ignore)
    if ($paths.Count -gt 0) {
        return (Get-VSBuildTool)
    }

    # Path for MSBuild 2015
    $paths = @(Resolve-Path "C:\Program Files (x86)\MSBuild\14.0\bin\MSBuild.exe" -ErrorAction Ignore)
    if ($paths.Count -gt 0) {
        return $paths[0].Path
    }

    # Path for MSBuild 2019
    $paths = @(Resolve-Path "C:\Program Files (x86)\Microsoft Visual Studio\2019\*\MSBuild\Current\Bin\*\MSBuild.exe" -ErrorAction Ignore)
    if ($paths.Count -gt 0) {
        return (Get-VSBuildTool)
    }

    return ""
}

function Get-VSBuildTool {
    foreach ($item in $paths) {
        if ($item.Path | Select-String -Pattern 'Community', 'Professional', 'Enterprise' -AllMatches) {
            return $item.Path
        }
    }
}

###############################################
## Function Helper for Assert-QueuesInstalled.
###############################################
function Test-MsmqQueueIsInstalled([string]$Queuename) {
    $queues = Get-MsmqQueue -QueueType Private | Select-String -Pattern $Queuename -CaseSensitive -SimpleMatch
    if ($queues.Count -lt 3) {
        Write-Host -foreground Red "[ERROR]: $Queuename queues not fully installed!`n"
        return "Failed"
    }
    Write-Host -foreground Green "$queuename exists."
    return "Passed"
}

##############################################################
## Checks that environment databases are installed correctly.
##############################################################
function Assert-EnvDatabasesInstalled {
    Write-Host "[STEP]: Verifying Databases are installed..."

    foreach ($database in $Databases) {
        if ((IsDBInstalled($database)) -eq "Failed") {
            return "Failed"
        }
    }

    Write-Host -foreground Green "Databases - Verified.`n"
    return "Passed"
}

#####################################################
## Function Helper for Assert-EnvDatabasesInstalled.
#####################################################
function IsDBInstalled([string]$DBName) {

    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.connectionstring = "Server=${sqlServerName};Database=${DBName};Integrated Security=True;"
        $conn.open()
        Write-Host -foreground Green "- ${DBName} installed."
        return "Passed"
    } catch {
        Write-Host -foreground Red "[ERROR]: Failed connecting to $DBNAME on ${sqlServerName}!`n"
        return "Failed"
    }
}

######################################################
## Checks that environment databases users are exist.
######################################################
function Assert-EnvDatabaseUsersCreated {
    Write-Host "[STEP]: Verifying database users exist..."

    foreach ($user in $DBUsers) {
        if ((Test-SQLLoginExists($user)) -eq "Passed") {
            continue
        } else {
            return "Failed"
        }
    }

    Write-Host -foreground Green "Database users - Verified.`n"
    return "Passed"
}

#######################################################
## Function Helper for Assert-EnvDatabaseUsersCreated.
#######################################################
function Test-SQLLoginExists([string]$SqlUser) {

    Import-Module SQLPS
    $smo = New-Object "Microsoft.SqlServer.Management.Smo.Server" $env:ComputerName
    if (($smo.logins).Name -contains $SqlUser) {
        Write-Host -foreground Green "* $SqlUser exists."
        return "Passed"
    }
    Write-Host -foreground Red "[ERROR]: $SqlUser doesn't exist!`n"
    return "Failed"
}

################################
## Checks that WebApp responds.
################################
function Assert-WebAppResponds {
    Write-Host "[STEP]: Verifying that Web App responds..."

    $webAppURL = "https://localhost/${envPrefix}/"
    $responseFailed = $false
    $HTTP_Response = $null

    try {
        Write-Host "Connecting to the Web App can take approx.: 1-2 minutes. If nothing will appear in these minutes please press <RETURN> button..."
        $HTTP_Request = [System.Net.WebRequest]::Create($webAppURL)
        $HTTP_Response = $HTTP_Request.GetResponse()
        $HTTP_Status = [int]$HTTP_Response.StatusCode
        if ($HTTP_Status -ne 200) {
            Write-Host -foreground Red "[ERROR]: Can not access ${webAppURL}. Please talk with admins to help you fix the problem!"
            $responseFailed = $true
        } else {
            Write-Host -foreground Green " Web App responds."
        }        
    } catch {
        Write-Host -foreground Red "[ERROR]: There are problems extracting info about the ${webAppURL}"
        $responseFailed = $true
    } finally {
        if($HTTP_Response -ne $null) {
            $HTTP_Response.Dispose()
        }
    }
    
    if ($responseFailed) {
        return "Failed"
    } else {
        return "Passed"
    }    
}

##############################
## Configures IIS for WebApp.
##############################
function Set-IIS {
    Write-Host "[STEP]: Setting up IIS binding for WebApp..."

    $providerPath = "IIS:\SSLBindings\0.0.0.0!443"
    
    if ($null -ne (Get-WebBinding -Name "Default Web Site" | where-object {$_.Protocol -eq "https"})) {
        Write-Host "There is already a binding"
        Remove-WebBinding -Name "Default Web Site" -Port 443 -Protocol "https"
        if((Test-Path $providerPath)) {
            # In case if there is SSL binding to localhost, we won't be able to set certificate for it.
            # We have to delete SSL binding and later add it with certificate
            Remove-Item $providerPath
        }
    }    
    New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol "https"

    # Check that certificate is on machine and set it for a website, otherwise create certificate
    $certificateInRoot = Get-ChildItem cert:\CurrentUser\Root -Recurse | Where-Object { $_.Subject -like "*DevLocalhost*" }
    $certificateInMy = Get-ChildItem Cert:\CurrentUser\My -Recurse | Where-Object { $_.Subject -like "*DevLocalhost*" }

    if (($null -ne $certificateInRoot) -and ($null -ne $certificateInMy) -and ($certificateInRoot.Thumbprint -eq $certificateInMy.Thumbprint)) {
        Get-Item $certificateInMy.PSPath | New-Item $providerPath
    } else {
        $certificate = New-SelfSignedCertificate `
        -Subject DevLocalhost `
        -DnsName localhost `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -NotBefore (Get-Date) `
        -NotAfter (Get-Date).AddYears(2) `
        -CertStoreLocation "cert:CurrentUser\My" `
        -FriendlyName "Dev Localhost Certificate" `
        -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature, KeyEncipherment, DataEncipherment `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
        $certificatePath = 'Cert:\CurrentUser\My\' + ($certificate.ThumbPrint)
        
        $tmpPath = "C:\tmp"
        if(!(Test-Path $tmpPath)) {
            New-Item -ItemType Directory -Force -Path $tmpPath
        }
        
        $pfxPassword = Read-Host "Please enter password for pfx (Password Complexity should be strong)" -AsSecureString
        $pfxFilePath = "c:\tmp\localhost.pfx"
        $cerFilePath = "c:\tmp\localhost.cer"
        
        Export-PfxCertificate -Cert $certificatePath -FilePath $pfxFilePath -Password $pfxPassword
        Export-Certificate -Cert $certificatePath -FilePath $cerFilePath
        
        Import-PfxCertificate -FilePath $pfxFilePath Cert:\LocalMachine\My -Password $pfxPassword -Exportable
        Import-Certificate -FilePath $cerFilePath -CertStoreLocation Cert:\CurrentUser\Root -Confirm
        
        Get-Item $certificatePath | New-Item $providerPath

        # optionally delete the physical certificates (don't delete the pfx file as you need to copy this to your app directory)
        Remove-Item $cerFilePath
    }
    Write-Host -foreground Green "Finished setting up IIS binding.`n"
}
