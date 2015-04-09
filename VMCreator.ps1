<# 	
  .NOTES
Copyright 2014 (c) Microsoft Corporation.  All rights reserved.

A WSSC CAT Solution Created by Rob Willis
	
In collaboration with:
PowerShell Deployment Toolkit Team (PDT)
America Enterprise Services - Azure IaaS Center of Expertise (COE)
Service Provider Operational Readiness Kit (ORK)
Datacenter and Cloud Infrastrucutre Services (COE)
               	
File:		VMCreator.ps1
	
Pre-Reqs:	Windows Server 2012 or Windows Server 2012 R2, and Windows PowerShell 4.0	
				
Version: 	2.65.5

Contributors:    Rob Willis, Robert Larson, Joel Stidley, David McFarlane-Smith, Joze Markic


 .SYNOPSIS
    VMCreator is part of The PowerShell Deployment Toolkit and is used to deploy virtual machines to Hyper-V servers.
  
 .DESCRIPTION
	This script it used to deploy virtual machines to Hyper-V servers as part of the PDT deployment process. 
  
	 		
 .EXAMPLE
	C:\PS> .\VMCreator.ps1 -Setup C:\PDT\VMs
	
	Description
	-----------
	This command creates virtual machines using the Variable.xml in the local directory. The C:\PDT\VMs directory is set as the root directory for copying customization scripts to each virtual machine.
	
 .EXAMPLE
	C:\PS> .\VMCreator.ps1 -Setup C:\PDT\VMs -EnableLogging
	
	Description
	-----------
	This command creates virtual machines using the Variable.xml in the local directory. The C:\PDT\VMs directory is set as the root directory for copying customization scripts to each virtual machine.
	The EnableLogging switch creates a transcript for VMCreator that will be placed in the local directory.
	
 .EXAMPLE
	C:\PS> .\VMCreator.ps1 -Setup C:\PDT\VMs -Path C:\PDT
	
	Description
	-----------
	This command creates virtual machines using the files in the C:\PDT directory. The C:\PDT\VMs directory is set as the root directory for copying customization scripts to each virtual machine.
	
	
 .PARAMETER Setup
	This parameter is used to specify the root directory for copying customization scripts to virtual machines. The directories in this location must be named the same as the virtual machine you will copy the files to during deployment.

 .PARAMETER EnableLogging
	This switch enables a log to be created of the virtual machine creation process.
	
 .PARAMETER Path
	This parameter is used to specify the path to the Variable.xml, Workflow.xml, Installer.ps1, and any Extender files that will be used.

 .PARAMETER SkipValidation
	This switch disables validation.
	
 .PARAMETER MaxStage
	This parameter allows you to configure how much of the deployment that VMCreator will complete. Valid options are: 1Admin, 2ServerFeatures, 3SQLClusters, 4SQL, 5Prereqs, 6Roles, 7Integration. Each stage includes the actions of the previous stage.

 .INPUTS
           None.

 .OUTPUTS
           None.

 .LINK
	http://aka.ms/pdt
#>  


Param
(
    [Parameter(Mandatory=$false,Position=0)]
    [String]$Path = (Get-Location),

    [Parameter(Mandatory=$false)]
    [String]$Setup,

    [Parameter(Mandatory=$false)]
    [String]$Mode,

    [Parameter(Mandatory=$false)]
    [Switch]$SkipValidation = $false,
	
	[Parameter(Mandatory=$false)]
	[Switch]$EnableLogging = $false,

    [Parameter(Mandatory=$false)]
    [ValidateSet("1Admin","2ServerFeatures","3SQLClusters","4SQL","5Prereqs","6Roles","7Integration")]
    [String]$MaxStage = "7Integration"
)

$host.UI.RawUI.BackgroundColor = "Black"; Clear-Host

# Enable logging
If ($EnableLogging)
{
	$Script:Path = Get-Location
	$Script:ScriptLog = "$path\VMCreator-" + (Get-Date -f yy.MM.dd-HH.mm.ss) + ".log"
	Start-Transcript -Path $Script:ScriptLog
}

# Elevate
$StartDate=Get-Date ; Write-Host "VMCreator started at: $StartDate"
Write-Host "Checking for elevation... " -NoNewline
$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
if (($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) -eq $false)  {
    $ArgumentList = "-noprofile -noexit -file `"{0}`" -Path `"$Path`" -MaxStage $MaxStage"
    If ($Setup) {$ArgumentList = $ArgumentList + " -Setup $Setup"}
    If ($Mode) {$ArgumentList = $ArgumentList + " -Mode $Mode"}
    Write-Host "elevating"
    Start-Process powershell.exe -Verb RunAs -ArgumentList ($ArgumentList -f ($myinvocation.MyCommand.Definition))
    Exit
}

$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$Validate = $true

# Check PS host
If ($Host.Name -ne 'ConsoleHost') {
    $Validate = $false
    Write-Host "VMCreator.ps1 should not be run from ISE" -ForegroundColor Red
}

# Check OS version
If ((Get-WmiObject -Class Win32_OperatingSystem).Version.Split(".")[2] -lt 9200) {
    $Validate = $false
    Write-Host "VMCreator.ps1 should be run from Windows Server 2012 or Windows 8 or later" -ForegroundColor Red
}

# Change to path
If (Test-Path $Path -PathType Container) {
    Set-Location $Path
} Else {
    $Validate = $false
    Write-Host "Invalid path" -ForegroundColor Red
}

Function Get-Value ($Value,$Count) {
    If ((Invoke-Expression ("`$Variable.Installer.VMs.VM | Where-Object {`$_.Count -eq `$Count} | ForEach-Object {`$_.$Value}")) -ne $null) {
        Invoke-Expression ("Return `$Variable.Installer.VMs.VM | Where-Object {`$_.Count -eq `$Count} | ForEach-Object {`$_.$Value}")
    } Else {
        Invoke-Expression ("Return `$Variable.Installer.VMs.Default.$Value")
    }
}

Function Get-VMKVP ($VMName,$VMHost,$KVPName) {
    $Query = "Select * from MSVM_ComputerSystem where ElementName='" + $VMName + "'"
    $VM = Get-WMIObject -Namespace root\virtualization\v2 -Query $Query -ComputerName $VMHost
    If ($VM -ne $null) {
        $Query = "Associators of {$VM} where AssocClass=MSVM_SystemDevice ResultClass=Msvm_KvpExchangeComponent"
        $KVPExchange = Get-WMIObject -Namespace root\virtualization\v2 -Query $Query -ComputerName $VMHost
        ForEach($KVPElement in $KVPExchange.GuestIntrinsicExchangeItems) {
            $XMLKVPElement = [XML]$KVPElement
            ForEach($XMLEntry in $XMLKVPElement.INSTANCE.PROPERTY) {
                If ($XMLEntry.NAME -eq "Name") {
                    $Name = $XMLEntry.VALUE
                    If ($Name -eq $KVPName) {$KVPData = $Data}
                }
                If ($XMLEntry.NAME -eq "Data") { $Data = $XMLEntry.VALUE }
            }
        }
    }
    Return $KVPData
}

Write-Host "Importing Hyper-V module"
If (!(Get-Module Hyper-V)) {Import-Module Hyper-V -ErrorAction SilentlyContinue}

If (Get-Module Hyper-V) {
    
    Write-Host "Getting VMCreator input"

    $Validate = $true
    Write-Host ""

    If (Test-Path ".\Workflow.xml") {
        try {$Workflow = [XML] (Get-Content ".\Workflow.xml")} catch {$Validate = $false;Write-Host "Invalid Workflow.xml" -ForegroundColor Red}
    } Else {
        $Validate = $false
        Write-Host "Missing Workflow.xml" -ForegroundColor Red
    }
    If (Test-Path "$Path\Extender*.xml") {
        Get-ChildItem -Path "$Path\Extender*.xml" | ForEach-Object {
            $ExtenderFile = $_.Name
            try {$Extender = [XML] (Get-Content "$Path\$ExtenderFile")} catch {$Validate = $false;Write-Host "Invalid Extender.xml" -ForegroundColor Red}
            If ($Validate) {
                $Extender.Installer.ServerFeatures | Where-Object {$_ -ne $null} | ForEach-Object {
                    $ExtenderServerFeaturesOSVersion = $_.OSVersion
                    $_.Group | Where-Object {$_ -ne $null} | ForEach-Object {
                        $ExtenderServerFeaturesGroup = $_.Name
                        $_.ServerFeature | Where-Object {$_ -ne $null} | ForEach-Object {
                            $ExtenderServerFeature = $_
                            If (!($Workflow.Installer.ServerFeatures | Where-Object {$_.OSVersion -eq $ExtenderServerFeaturesOSVersion} | ForEach-Object {$_.Group} | Where-Object {$_.Name -eq $ExtenderServerFeaturesGroup} | ForEach-Object {$_.ServerFeature} | Where-Object {$_.Name -eq $ExtenderServerFeature.Name})) {
                                ($Workflow.Installer.ServerFeatures | Where-Object {$_.OSVersion -eq $ExtenderServerFeaturesOSVersion} | ForEach-Object {$_.Group} | Where-Object {$_.Name -eq $ExtenderServerFeaturesGroup}).AppendChild($Workflow.ImportNode($ExtenderServerFeature,$true)) | Out-Null
                            }
                        }
                    }
                }
                $Extender.Installer.Installables.Installable | Where-Object {$_ -ne $null} | ForEach-Object {
                    $ExtenderInstallable = $_
                    If (!($Workflow.Installer.Installables.Installable | Where-Object {$_.Name -eq $ExtenderInstallable.Name})) {

                        $Workflow.Installer.Installables.AppendChild($Workflow.ImportNode($ExtenderInstallable,$true)) | Out-Null


                    }
                }
                $Extender.Installer.Components.Component | Where-Object {$_ -ne $null} | ForEach-Object {
                    $ExtenderComponent = $_
                    If (!($Workflow.Installer.Components.Component | Where-Object {$_.Name -eq $ExtenderComponent.Name})) {

                        $Workflow.Installer.Components.AppendChild($Workflow.ImportNode($ExtenderComponent,$true)) | Out-Null


                    }
                }
                $Extender.Installer.SQL.SQL | Where-Object {$_ -ne $null} | ForEach-Object {
                    $ExtenderSQL = $_
                    If (!($Workflow.Installer.SQL.SQL | Where-Object {$_.Version -eq $ExtenderSQL.Version})) {

                        $Workflow.Installer.SQL.AppendChild($Workflow.ImportNode($ExtenderSQL,$true)) | Out-Null


                    }
                }
                $Extender.Installer.Roles.Role | Where-Object {$_ -ne $null} | ForEach-Object {
                    $ExtenderRole = $_
                    If (!($Workflow.Installer.Role.Role | Where-Object {$_.Name -eq $ExtenderRole.Name})) {



                        $Workflow.Installer.Roles.AppendChild($Workflow.ImportNode($ExtenderRole,$true)) | Out-Null
                    }
                }
                $Extender.Installer.Integrations.Integration | Where-Object {$_ -ne $null} | ForEach-Object {
                    $ExtenderIntegration = $_
                    If (!($Workflow.Installer.Integrations.Integration | Where-Object {$_.Name -eq $ExtenderIntegration.Name})) {



                        $Workflow.Installer.Integrations.AppendChild($Workflow.ImportNode($ExtenderIntegration,$true)) | Out-Null
                    }
                }
            }
        }
    }

    If (Test-Path ".\Variable.xml") {
        try {$Variable = [XML] (Get-Content ".\Variable.xml")} catch {$Validate = $false;Write-Host "Invalid Variable.xml" -ForegroundColor Red}
    } Else {
        $Validate = $false
        Write-Host "Missing Variable.xml" -ForegroundColor Red
    }

    If ($Validate) {
        # Get how many VMs to create
        $VMCount = $Variable.Installer.VMs.Count
        Write-Host "Creating $VMCount VMs"
        $Domain = $Variable.Installer.VMs.Domain.Name
        $DomainExisting = $Variable.Installer.VMs.Domain.Existing
        If ($DomainExisting -eq 'True') {
            $DomainExisting = $true
        } Else {
            $DomainExisting = $false
        }
        $AutonamePrefix = $Variable.Installer.VMs.Default.VMName.Prefix
        [Int]$AutonameSequence = $Variable.Installer.VMs.Default.VMName.Sequence
        $AutoMACPrefix = $Variable.Installer.VMs.Default.NetworkAdapter.MAC.Prefix
        [Int]$AutoMACSequence = $Variable.Installer.VMs.Default.NetworkAdapter.MAC.Sequence
        $AutoIPPrefix = $Variable.Installer.VMs.Default.NetworkAdapter.IP.Prefix
        [Int]$AutoIPSequence = $Variable.Installer.VMs.Default.NetworkAdapter.IP.Sequence
        $InstallerServiceAccount = ($Variable.Installer.Variable | Where-Object {$_.Name -eq "InstallerServiceAccount"}).Value
        $InstallerServiceAccountPassword = ($Variable.Installer.Variable | Where-Object {$_.Name -eq "InstallerServiceAccountPassword"}).Value
        $InstallerServiceAccountDomain = $InstallerServiceAccount.Split("\")[0]
        $InstallerServiceAccountUsername = $InstallerServiceAccount.Split("\")[1]

        $AutonameCount = 0
        $AutoMACCount = 0
        $AutoIPCount = 0

        If ((($Domain -ne $null) -and !($DomainExisting)) -and !($SkipValidation)) {
            Function Set-ScriptVariable ($Name,$Value) {
                Invoke-Expression ("`$Script:" + $Name + " = `"" + $Value + "`"")
                If (($Name.Contains("ServiceAccount")) -and !($Name.Contains("Password")) -and ($Value -ne "")) {
                    Invoke-Expression ("`$Script:" + $Name + "Domain = `"" + $Value.Split("\")[0] + "`"")
                    Invoke-Expression ("`$Script:" + $Name + "Username = `"" + $Value.Split("\")[1] + "`"")
                }
            }
            $Servers = @($Variable.Installer.Roles.Role | Where-Object {($_.Existing -ne "True") -and ($_.SQLCluster -ne "True")} | Sort-Object {$_.Server} -Unique | ForEach-Object {$_.Server})
            $SQLClusters = @($Variable.Installer.Roles.Role | Where-Object {($_.Existing -ne "True") -and ($_.SQLCluster -eq "True")} | ForEach-Object {$_.Server})
            $SQLClusters | ForEach-Object {
                $SQLCluster = $_
                $SQLClusterNodes = $Variable.Installer.SQL.Cluster | Where-Object {$_.Cluster -eq $SQLCluster} | ForEach-Object {$_.Node.Server}
                $Servers += $SQLClusterNodes
            }
            $Servers = $Servers | Sort-Object -Unique
            $Roles = @($Variable.Installer.Roles.Role)
            $SystemDrive = $env:SystemDrive
            $Workflow.Installer | ForEach-Object {$_.Variable} | Where-Object {$_.Name -ne $null} | ForEach-Object {
                Set-ScriptVariable -Name $_.Name -Value $_.Value
            }
            $Variable.Installer | ForEach-Object {$_.Variable} | Where-Object {$_.Name -ne $null} | ForEach-Object {
                Set-ScriptVariable -Name $_.Name -Value $_.Value
            }
            # Validate FQDN
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating FQDN..."
                Write-Host ""
                $Servers | ForEach-Object {
                    Write-Host "    Server: $_... " -NoNewline
                    If (@($_.Split(".")).Count -ge 3) {
                        Write-Host "Passed" -ForegroundColor Green
                    } Else {
                        Write-Host "Failed" -ForegroundColor Red
                        Write-Host "      FQDN required" -ForegroundColor Red
                        $validate = $false
                    }
                }
                Start-Sleep 1
            }

            # Validate dependencies
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating role dependencies..."
                Write-Host ""
                $Roles | ForEach-Object {
                    $RoleValidate = $true
                    $Role = $_.Name
                    If ($Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Dependency}) {
                        Write-Host "    Role: $Role... " -NoNewline
                        $Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Dependency} | ForEach-Object {
                            $Dependency = $_.Name
                            If (!($Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Dependency})) {
                                $RoleValidate = $false
                            }
                        }
                        If ($RoleValidate) {
                            Write-Host "Passed" -ForegroundColor Green
                        } Else {
                            Write-Host "Failed" -ForegroundColor Red
                            $Validate = $false
                            $Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Dependency} | ForEach-Object {
                                $Dependency = $_.Name
                                If (!($Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Dependency})) {
                                    Write-Host "      Missing dependency $Dependency" -ForegroundColor Red
                                }
                            }
                        }
                    }
                }
                Start-Sleep 1
            }

            # Validate role combinations
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating role combinations..."
                Write-Host ""
                $Roles | ForEach-Object {
                    $RoleValidate = $true
                    $Role = $_.Name
                    $Server = $_.Server
                    $Instance = $_.Instance
                    If ($Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Validation.Combinations}) {        
                        Write-Host "    Role: $Role... " -NoNewline
                        $Variable.Installer.Roles.Role | Where-Object {($_.Server -eq $Server) -and ($_.Instance -eq $Instance)} | ForEach-Object {$_.Name} | ForEach-Object {
                            $Combination = $_
                            If (($Role -ne $Combination) -and !(($Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Validation.Combinations.Combination} | Where-Object {$_ -eq $Combination}))) {
                                $RoleValidate = $false
                            }
                        }
                        If ($RoleValidate) {
                            Write-Host "Passed" -ForegroundColor Green
                        } Else {
                            Write-Host "Failed" -ForegroundColor Red
                            $Validate = $false
                            $Variable.Installer.Roles.Role | Where-Object {($_.Server -eq $Server) -and ($_.Instance -eq $Instance)} | ForEach-Object {$_.Name} | ForEach-Object {
                                $Combination = $_
                                If (($Role -ne $Combination) -and !(($Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Validation.Combinations.Combination} | Where-Object {$_ -eq $Combination}))) {
                                    Write-Host "      Unsupported combination: $Combination" -ForegroundColor Red
                                }
                            }
                        }
                    }
                }
                Start-Sleep 1
            }

            # Validate role instance count
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating role instance count..."
                Write-Host ""
                $Roles | ForEach-Object {
                    $Role = $_.Name
                    $Server = $_.Server
                    If ($Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Validation.Multiple} | Where-Object {$_ -eq "False"}) {
                        Write-Host "    Role: $Role... " -NoNewline
                        If (@($Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Role}).Count -eq 1) {
                            Write-Host "Passed" -ForegroundColor Green
                        } Else {
                            Write-Host "Failed" -ForegroundColor Red
                            Write-Host "      $Role can have only one instance" -ForegroundColor Red
                            $Validate = $false
                        }
                    }
                }
                Start-Sleep 1
            }

            # Validate required variables
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating required variables..."
                Write-Host ""
                Write-Host "    Global variables"
                $Workflow.Installer.Variable | Where-Object {$_.Required -eq "True"} | ForEach-Object {
                    $RequiredVariable = $_.Name
                    Write-Host "      Variable: $RequiredVariable... " -NoNewline
                    If ((Get-Item "Variable:$RequiredVariable" -ErrorAction SilentlyContinue).Value) {
                        Write-Host "Passed" -ForegroundColor Green
                    } Else {
                        Write-Host "Failed" -ForegroundColor Red
                        $Validate = $false
                    }
                }
                $Components = $Workflow.Installer.Components.Component | ForEach-Object {$_.Name}
                $Components | ForEach-Object {
                    $Component = $_
                    If ($Workflow.Installer.Components.Component | Where-Object {$_.Name -eq $Component} | ForEach-Object {$_.Variable | Where-Object {$_.Required -eq "True"}}) {
                        $CR = $False
                        $Workflow.Installer.Roles.Role | Where-Object {$_.Component -eq $Component} | ForEach-Object {
                            $Role = $_.Name
                            $Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {
                                If ($CR -eq $False) {
                                    Write-Host "    $Component Variables"
                                    $CR = $True
                                    $Workflow.Installer.Components.Component | Where-Object {$_.Name -eq $Component} | ForEach-Object {$_.Variable} | Where-Object {$_.Name -ne $null} | ForEach-Object {
                                        Set-ScriptVariable -Name $_.Name -Value $_.Value
                                    }
                                    $Variable.Installer.Components.Component | Where-Object {$_.Name -eq $Component} | ForEach-Object {$_.Variable} | Where-Object {$_.Name -ne $null} | ForEach-Object {
                                        Set-ScriptVariable -Name $_.Name -Value $_.Value
                                    }
                                    $Workflow.Installer.Components.Component | Where-Object {$_.Name -eq $Component} | ForEach-Object {$_.Variable | Where-Object {$_.Required -eq "True"}} | ForEach-Object {
                                        $RequiredVariable = $_.Name
                                        Write-Host "      Variable: $RequiredVariable... " -NoNewline
                                        If ((Get-Item "Variable:$RequiredVariable" -ErrorAction SilentlyContinue).Value) {
                                            Write-Host "Passed" -ForegroundColor Green
                                        } Else {
                                            Write-Host "Failed" -ForegroundColor Red
                                            $Validate = $false
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Start-Sleep 1
            }

            # Validate SQL variables
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating SQL variables..."
                Write-Host ""
                $Workflow.Installer.Roles.Role | Where-Object {$_.SQL -eq "True"} | ForEach-Object {
                    $RoleValidate = $True
                    $Role = $_.Name
                    $Variable.Installer.Roles.Role | Where-Object {($_.Name -eq $Role) -and ($_.SQLCluster -ne "True")} | ForEach-Object {
                        $Server = $_.Server
                        Write-Host "    Role: $Role"
                        Write-Host "      Instance... " -NoNewline
                        If ($Variable.Installer.Roles.Role | Where-Object {($_.Name -eq $Role) -and ($_.Instance -ne $null)}) {
                            $Instance = $_.Instance
                            Write-Host "Passed" -ForegroundColor Green
                        } Else {
                            Write-Host "Failed" -ForegroundColor Red
                            Write-Host "        SQL Server instance not specified" -ForegroundColor Red
                            $Validate = $False
                            $RoleValidate = $False
                        }
                        If ($RoleValidate) {
                            Write-Host "      SQL Server version for instance... " -NoNewline
                            If ($Variable.Installer.SQL.Instance | Where-Object {($_.Server -eq $Server) -and ($_.Instance -eq $Instance) -and ($_.Version -ne $null)}) {
                                $SQLVersion = $Variable.Installer.SQL.Instance | Where-Object {($_.Server -eq $Server) -and ($_.Instance -eq $Instance)} | ForEach-Object {$_.Version}
                                If ($Workflow.Installer.SQL.SQL | Where-Object {$_.Version -eq $SQLVersion}) {
                                    Write-Host "Passed" -ForegroundColor Green
                                } Else {
                                    Write-Host "Failed" -ForegroundColor Red
                                    Write-Host "        Invalid SQL Server version" -ForegroundColor Red
                                    $Validate = $False
                                    $RoleValidate = $False
                                }
                            } Else {
                                Write-Host "Failed" -ForegroundColor Red
                                Write-Host "        SQL Server version not specified" -ForegroundColor Red
                                $Validate = $False
                                $RoleValidate = $False
                            }
                        }
                        If ($RoleValidate) {
                            $Workflow.Installer.SQL.SQL | Where-Object {$_.Version -eq $SQLVersion} | ForEach-Object {$_.Variable} | Where-Object {$_.Required -eq "True"} | ForEach-Object {
                                $RequiredVariable = $_.Name
                                $Workflow.Installer.SQL.SQL | Where-Object {$_.Version -eq $SQLVersion} | ForEach-Object {$_.Variable} | Where-Object {$_.Name -ne $null} | ForEach-Object {
                                    Set-ScriptVariable -Name $_.Name -Value $_.Value
                                }
                                $Variable.Installer.SQL.Server | Where-Object {($_.Server -eq $Server)} | ForEach-Object {$_.Variable} | Where-Object {$_.Name -ne $null} | ForEach-Object {
                                    Set-ScriptVariable -Name $_.Name -Value $_.Value
                                }
                                $Variable.Installer.SQL.Instance | Where-Object {($_.Server -eq $Server) -and ($_.Instance -eq $Instance)} | ForEach-Object {$_.Variable} | Where-Object {$_.Name -ne $null} | ForEach-Object {
                                    Set-ScriptVariable -Name $_.Name -Value $_.Value
                                }
                                Write-Host "      Variable: $RequiredVariable... " -NoNewline
                                If ((Get-Item "Variable:$RequiredVariable" -ErrorAction SilentlyContinue).Value) {
                                    Write-Host "Passed" -ForegroundColor Green
                                } Else {
                                    Write-Host "Failed" -ForegroundColor Red
                                    $Validate = $false
                                }
                            }
                        }
                    }
                }
                Start-Sleep 1
            }

            # Validate SQL instance
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating SQL instance..."
                Write-Host ""
                $Workflow.Installer.Roles.Role | Where-Object {$_.Validation.SQL.Instance} | ForEach-Object {
                    $Role = $_.Name
                    $Roles | Where-Object {$_.Name -eq $Role} | ForEach-Object {
                        Write-Host "    Role: $Role... " -NoNewline
                        $SQLInstance = $Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Instance}
                        If ($Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Validation.SQL.Instance} | Where-Object {$_ -eq $SQLInstance}) {
                            Write-Host "Passed" -ForegroundColor Green
                        } Else {
                            Write-Host "Failed" -ForegroundColor Red
                            Write-Host "      Invalid SQL instance $SQLInstance" -ForegroundColor Red
                            $Validate = $false
                        }
                    }
                }
                Start-Sleep 1
            }

            # Validate SQL port
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating SQL port..."
                Write-Host ""
                $Workflow.Installer.Roles.Role | Where-Object {$_.Validation.SQL.Port -eq "True"} | ForEach-Object {
                    $Role = $_.Name
                    $Roles | Where-Object {$_.Name -eq $Role} | ForEach-Object {
                        Write-Host "    Role: $Role... " -NoNewline
                        $SQLServer = $Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Server}
                        $SQLInstance = $Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Instance}
                        $SQLCluster = $Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.SQLCluster}
                        If ($SQLCluster -eq "True") {
                            $SQLPort = $Variable.Installer.SQL.Cluster | Where-Object {$_.Cluster -eq $SQLServer} | ForEach-Object {$_.Port}
                        } Else {
                            $SQLPort = $Variable.Installer.SQL.Instance | Where-Object {($_.Server -eq $SQLServer) -and ($_.Instance -eq $SQLInstance)} | ForEach-Object {$_.Port}
                        }
                        If (($SQLInstance -eq "MSSQLSERVER") -or ($SQLPort -ne $null)) {
                            Write-Host "Passed" -ForegroundColor Green
                        } Else {
                            Write-Host "Failed" -ForegroundColor Red
                            Write-Host "      Missing port for SQL server $SQLServer instance $SQLInstance" -ForegroundColor Red
                            $Validate = $false
                        }
                    }
                }
                Start-Sleep 1
            }

            # Validate NLB configuration
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating NLB configuration..."
                Write-Host ""
                $Components = $Workflow.Installer.Components.Component | ForEach-Object {$_.Name}
                $Components | ForEach-Object {
                    $Component = $_
                    $CR = $False
                    $Workflow.Installer.Roles.Role | Where-Object {$_.Component -eq $Component} | ForEach-Object {
                        $Role = $_.Name
                        $Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {
                            If ($CR -eq $False) {
                                $Workflow.Installer.Components.Component | Where-Object {$_.Name -eq $Component} | ForEach-Object {$_.Variable} | Where-Object {$_.Name -ne $null} | ForEach-Object {
                                    Set-ScriptVariable -Name $_.Name -Value $_.Value
                                }
                                $Variable.Installer.Components.Component | Where-Object {$_.Name -eq $Component} | ForEach-Object {$_.Variable} | Where-Object {$_.Name -ne $null} | ForEach-Object {
                                    Set-ScriptVariable -Name $_.Name -Value $_.Value
                                }
                                $Workflow.Installer.Roles.Role | Where-Object {($_.Component -eq $Component) -and ($_.Validation.NLB -eq "True")} | ForEach-Object {
                                    $Role = $_.Name
                                    $Roles | Where-Object {$_.Name -eq $Role} | ForEach-Object {
                                        If (!($CR)) {Write-Host "    $Component NLB configuration"}
                                        $CR = $true
                                        If ((Invoke-Expression ("`$" + $Role.Replace(" ","") + "NLBConfig")) -eq "True") {
                                            Write-Host "      Role: $Role... " -NoNewline
                                            If (!(Invoke-Expression ("`$" + $Role.Replace(" ","") + "NLBName")) -or !(Invoke-Expression ("`$" + $Role.Replace(" ","") + "NLBIPv4"))) {
                                                Write-Host "Failed" -ForegroundColor Red
                                                Write-Host "        Missing either NLBName or NLBIPv4 variables" -ForegroundColor Red
                                                $Validate = $false
                                            } Else {
                                                If (((Invoke-Expression ("`$" + $Role.Replace(" ","") + "NLBName")).Split(".").Count -eq 1) -or ((Invoke-Expression ("`$" + $Role.Replace(" ","") + "NLBIPv4")).Split(".").Count -eq 1)) {
                                                    Write-Host "Failed" -ForegroundColor Red
                                                    Write-Host "        NLBName and NLBIPv4 must be FQDN and IPv4 address" -ForegroundColor Red
                                                    $Validate = $false
                                                } Else {
                                                    Write-Host "Passed" -ForegroundColor Green
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Start-Sleep 1
            }

            # Validate NLB combinations
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating NLB combinations..."
                Write-Host ""
                $Roles | Where-Object {$_ -ne $null} | ForEach-Object {
                    $RoleValidate = $true
                    $Role = $_.Name
                    $Server = $_.Server
                    $VR = $true
                    If ((Invoke-Expression ("`$" + $Role.Replace(" ","") + "NLBConfig")) -eq "True") {
                        $IPv4 = Invoke-Expression ("`$" + $Role.Replace(" ","") + "NLBIPv4")
                        If ($Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {$_.Validation.NLB}) {
                            Write-Host "    Role: $Role... " -NoNewline
                            $Variable.Installer.Roles.Role | Where-Object {$_.Server -eq $Server} | ForEach-Object {$_.Name} | ForEach-Object {
                                If (Invoke-Expression ("`$" + $_.Replace(" ","") + "NLBIPv4")) {
                                    If ((Invoke-Expression ("`$" + $_.Replace(" ","") + "NLBIPv4")) -ne $IPv4) {
                                    If ($VR) {
                                            $VR = $false
                                            Write-Host "Failed" -ForegroundColor Red
                                            Write-Host "      IPv4 addresses must be the same on combined NLB servers" -ForegroundColor Red
                                            $Validate = $False
                                        }
                                    }
                                }
                            }
                            $Variable.Installer.Roles.Role | Where-Object {$_.Server -ne $Server} | ForEach-Object {$_.Name} | ForEach-Object {
                                If (Invoke-Expression ("`$" + $_.Replace(" ","") + "NLBIPv4")) {
                                    If ((Invoke-Expression ("`$" + $_.Replace(" ","") + "NLBIPv4")) -eq $IPv4) {
                                    If ($VR) {
                                            $VR = $false
                                            Write-Host "Failed" -ForegroundColor Red
                                            Write-Host "      IPv4 addresses must be different on different NLB servers" -ForegroundColor Red
                                            $Validate = $False
                                        }
                                    }
                                }
                            }
                        }
                        If ($VR) {Write-Host "Passed" -ForegroundColor Green}
                    }
                }
                Start-Sleep 1
            }

            # Validate media
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating media..."
                Write-Host ""
                # Get SQL versions
                $Installables = @("Windows Server 2012 R2","Windows Server 2012")
                $Servers | ForEach-Object {
                    $Server = $_
                    $Variable.Installer.Roles.Role | Where-Object {($_.Server -eq $Server) -and ($_.Instance -ne $null)} | ForEach-Object {$_.Instance} | Sort-Object -Unique | ForEach-Object {
                        $Instance = $_
                        $Variable.Installer.SQL.Instance | Where-Object {($_.Server -eq $Server) -and ($_.Instance -eq $Instance)} | ForEach-Object {
                            $Installables += $_.Version
                        }
                    }
                }

                # Get roles
                $MRoles = @()
                $Servers | ForEach-Object {
                $Server = $_

                # Get roles for this server
                $MRoles += @($Variable.Installer.Roles.Role | Where-Object {$_.Server -eq $Server} | Where-Object {$_.Existing -ne "True"} | ForEach-Object {$_.Name})

                # Get SQL cluster roles for this server
                $Variable.Installer.SQL.Cluster | ForEach-Object {
                    $SQLCluster = $_.Cluster
                    $_.Node | Where-Object {$_.Server -eq $Server} | ForEach-Object {
                        $SQLClusterNode = $_.Server
                        $SQLClusterNodes = $Variable.Installer.Roles.Role | Where-Object {$_.Server -eq $SQLCluster} | ForEach-Object {$_.Name}
                        $MRoles += $SQLClusterNodes
                    }
                }

                # Get integrations for this server
                # For each role on this server...
                $MRoles | ForEach-Object {
                    $Role = $_
                    $Integration = $false
                    # ...find integrations targeted at that role
                    $Workflow.Installer.Integrations.Integration | Where-Object {$_.Target -eq $Role} | ForEach-Object {
                        $ThisIntegration = $_.Name
                        $Integration = $true
                        # Check that all integration dependencies exist in this deployment
                        $_.Dependency | ForEach-Object {
                            $Dependency = $_
                            If (!($Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Dependency})) {
                                $Integration = $false
                            }
                        }
                        If ($Integration) {
                            $MRoles += $ThisIntegration
                        }
                    }
                }
                }
                $MRoles = $MRoles | Sort-Object -Unique

                # Get installables
                $MRoles | ForEach-Object {
                    $Role = $_
                    $Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {
                        $_.Prerequisites | ForEach-Object {
                            $_.Prerequisite | ForEach-Object {
                                $Prerequisite = $_.Name
#                                If (!($Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Prerequisite})) {
                                    $Workflow.Installer.Installables.Installable | ForEach-Object {
                                        $InstallableName = $_.Name
                                        If ($_.Install | Where-Object {$_.Name -eq $Prerequisite}) {
                                            $Installables += $InstallableName
                                        }
                                    }
#                                }
                            }
                        }
                        $_.Install | ForEach-Object {
                            $Installables += $_.Installable
                        }
                    }
                }
                $Installables = $Installables | Sort-Object -Unique

                # Get additional installables
                $Installables | ForEach-Object {
                    $Installable = $_
                    $Workflow.Installer.Installables.Installable | Where-Object {$_.Name -eq $Installable} | ForEach-Object {
                        If ($_.AdditionalDownload) {
                            $_.AdditionalDownload | ForEach-Object {
                                $Installables += $_
                            }
                        }
                    }
                }
                $Installables = $Installables | Sort-Object -Unique

                # Validate media for each installable
                $Installables | ForEach-Object {
                    $Installable = $_
                    $Workflow.Installer.Installables.Installable | Where-Object {$_.Name -eq $Installable} | ForEach-Object {
                        If ($_.Variable) {
                            $_.Variable | ForEach-Object {
                                If (Get-Variable $_.Name -ErrorAction SilentlyContinue) {
                                    Set-Variable -Name $_.Name -Value $_.Value
                                } Else {        
                                    New-Variable -Name $_.Name -Value $_.Value
                                }
                            }
                        }
                    }
                    $Variable.Installer.Installables.Installable | Where-Object {$_.Name -eq $Installable} | ForEach-Object {
                        If ($_.Variable) {
                            $_.Variable | ForEach-Object {
                                If (Get-Variable $_.Name -ErrorAction SilentlyContinue) {
                                    Set-Variable -Name $_.Name -Value $_.Value
                                } Else {        
                                    New-Variable -Name $_.Name -Value $_.Value
                                }
                            }
                        }
                    }
                    $Workflow.Installer.Installables.Installable | Where-Object {$_.Name -eq $Installable} | ForEach-Object {
                        $DownloadName = $_.Name
                        If ($_.Download) {
                            $DownloadFolder = Invoke-Expression ($_.SourceFolder)
                            @($_.Download)[0] | ForEach-Object {
                                $DownloadItem = $_
                                $DownloadType = $_.Type
                                Write-Host "    $DownloadName... " -NoNewline
                                Switch ($DownloadType) {
                                    "Download" {
                                        $DownloadFile = $DownloadItem.File
                                        If (Test-Path "$Download\$DownloadFolder\$DownloadFile") {
                                            $DownloadFileType = $DownloadFile.Split(".")[$DownloadFile.Split(".").Count - 1]
                                            Switch ($DownloadFileType) {
                                                "exe" {
                                                    $Result = $false
													$DownloadFileVersion = $DownloadItem.FileVersion.Split("/")
                                                    $DownloadFileVersion | ForEach-Object {If ((Get-Item "$Download\$DownloadFolder\$DownloadFile").VersionInfo.ProductVersion -eq $_) {$Result = $true}}
													If ($Result){
                                                        Write-Host "Passed" -ForegroundColor Green
                                                    } Else {
                                                        Write-Host "Failed" -ForegroundColor Red
                                                        Write-Host "      $Download\$DownloadFolder\$DownloadFile incorrect version" -ForegroundColor Red
                                                        $Validate = $false
                                                    }
                                                    Break
                                                }
                                                Default {
                                                    $Result = $false
													$DownloadFileSize = $DownloadItem.FileSize.Split("/")
													$DownloadFileSize | ForEach-Object {If ((Get-Item "$Download\$DownloadFolder\$DownloadFile").Length -eq $_) {$Result = $true}}
													If ($Result){
                                                        Write-Host "Passed" -ForegroundColor Green
                                                    } Else {
                                                        Write-Host "Failed" -ForegroundColor Red
                                                        Write-Host "      $Download\$DownloadFolder\$DownloadFile incorrect size" -ForegroundColor Red
                                                        $Validate = $false
                                                    }
                                                }
                                            }
                                        } Else {
                                            Write-Host "Failed" -ForegroundColor Red
                                            Write-Host "      $Download\$DownloadFolder\$DownloadFile missing" -ForegroundColor Red
                                            $Validate = $false
                                        }
                                    }
                                    "DownloadRun" {
                                        $ExistingFile = @($DownloadItem.Run.ExistingFile)[0]
                                        If (Test-Path "$Download\$DownloadFolder\$ExistingFile") {
                                            $ExistingFileType = $ExistingFile.Split(".")[$ExistingFile.Split(".").Count - 1]
                                            Switch ($ExistingFileType) {
                                                "exe" {
													$Result = $false
                                                    $ExistingFileVersion = @($DownloadItem.Run)[0].FileVersion.Split("/")
													$ExistingFileVersion | ForEach-Object {If ((Get-Item "$Download\$DownloadFolder\$ExistingFile").VersionInfo.ProductVersion -eq $_) {$Result = $true}}
													
													If ($Result){
                                                        Write-Host "Passed" -ForegroundColor Green
                                                    } Else {
                                                        Write-Host "Failed" -ForegroundColor Red
                                                        Write-Host "      $Download\$DownloadFolder\$ExistingFile incorrect version" -ForegroundColor Red
                                                        $Validate = $false
                                                    }
                                                    Break
                                                }
                                                Default {
													$Result = $false
                                                    $ExistingFileSize = @($DownloadItem.Run)[0].FileSize.Split("/")
													$ExistingFileSize | ForEach-Object {If ((Get-Item "$Download\$DownloadFolder\$ExistingFile").Length -eq $_) {$Result = $true}}
													
													If ($Result){
                                                        Write-Host "Passed" -ForegroundColor Green
                                                    } Else {
                                                        Write-Host "Failed" -ForegroundColor Red
                                                        Write-Host "      $Download\$DownloadFolder\$ExistingFile incorrect size" -ForegroundColor Red
                                                        $Validate = $false
                                                    }
                                                }
                                            }
                                        } Else {
                                            Write-Host "Failed" -ForegroundColor Red
                                            Write-Host "      $Download\$DownloadFolder\$ExistingFile missing" -ForegroundColor Red
                                            $Validate = $false
                                        }
                                    }
                                    "DownloadExtract" {
                                        $ExistingFile = $DownloadItem.Extract.ExistingFile
                                        If (Test-Path "$Download\$DownloadFolder\$ExistingFile") {
                                            $ExistingFileType = $ExistingFile.Split(".")[$ExistingFile.Split(".").Count - 1]
                                            Switch ($ExistingFileType) {
                                                "exe" {
													$Result = $false
                                                    $ExistingFileVersion = @($DownloadItem.Extract)[0].FileVersion.Split("/")
                                                    $ExistingFileVersion | ForEach-Object {If ((Get-Item "$Download\$DownloadFolder\$ExistingFile").VersionInfo.ProductVersion -eq $_) {$Result = $true}}
													
													If ($Result){
                                                        Write-Host "Passed" -ForegroundColor Green
                                                    } Else {
                                                        Write-Host "Failed" -ForegroundColor Red
                                                        Write-Host "      $Download\$DownloadFolder\$ExistingFile incorrect version" -ForegroundColor Red
                                                        $Validate = $false
                                                    }
                                                    Break
                                                }
                                                Default {
													$Result = $false
                                                    $ExistingFileSize = @($DownloadItem.Extract)[0].FileSize.Split("/")
                                                    $ExistingFileSize | ForEach-Object {If ((Get-Item "$Download\$DownloadFolder\$ExistingFile").Length -eq $_) {$Result = $true}}
													
													If ($Result){
                                                        Write-Host "Passed" -ForegroundColor Green
                                                    } Else {
                                                        Write-Host "Failed" -ForegroundColor Red
                                                        Write-Host "      $Download\$DownloadFolder\$ExistingFile incorrect size" -ForegroundColor Red
                                                        $Validate = $false
                                                    }
                                                }
                                            }
                                        } Else {
                                            Write-Host "Failed" -ForegroundColor Red
                                            Write-Host "      $Download\$DownloadFolder\$ExistingFile missing" -ForegroundColor Red
                                            $Validate = $false
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Start-Sleep 1
            }

            # Validate servers
            If ($Validate) {
                Clear-Host
                Write-Host "Validating (Local)..."
                Write-Host ""
                Write-Host "  Validating servers..."
                Write-Host ""
                $Servers | ForEach-Object {
                    $Server = $_
                    $ServerFound = $false
                    Write-Host "    $Server`: " -NoNewline
                    For ($i = 1; $i -le $VMCount; $i++) {
                        # Get the VM name - specific or autonamed
                        If ((Get-Value -Count $i -Value "VMName").GetType().FullName -eq "System.String") {
                            $VMName = Get-Value -Count $i -Value "VMName"
                        } Else {
                            $VMName = $AutonamePrefix + ($AutonameSequence + $AutonameCount).ToString("00")
                            $AutonameCount ++
                        }
                        If ("$VMName.$Domain" -eq $Server) {$ServerFound = $true}
                    }
                    If ($ServerFound) {
                        Write-Host "Passed" -ForegroundColor Green
                    } Else {
                        Write-Host "Failed" -ForegroundColor Red
                        Write-Host "      $Server is not created in this deployment" -ForegroundColor Red
                        $Validate = $false
                    }
                }
                Start-Sleep 1
            }
        }

        Write-Host ""
        If (!($Validate)) {
            Write-Host "Validation failed" -ForegroundColor Red
            Write-Host ""
            Exit
        }

        $AutonameCount = 0

        For ($i = 1; $i -le $VMCount; $i++) {

            $CreateVM = $true

            $DataDrive = 0
            $DataDisk = 0
            $DiskPrepCount = 0

            Write-Host ""
            # Get the VM name - specific or autonamed
            If ((Get-Value -Count $i -Value "VMName").GetType().FullName -eq "System.String") {
                $VMName = Get-Value -Count $i -Value "VMName"
            } Else {
                $VMName = $AutonamePrefix + ($AutonameSequence + $AutonameCount).ToString("00")
                $AutonameCount ++
            }
            # Get the VM Generation
            $VMGen = Get-Value -Count $i -Value "VMGeneration"
            If ($VMGen -eq $null) {$VMGen = "1"}

            # Check required resources for creation exist

            # Get the VM host
            $VMHost = Get-Value -Count $i -Value "Host"
            If ($VMHost.Substring(0,3) -eq "~CL") {
                Switch ($VMHost) {
                    "~CLOdd" {
                        If (($env:ComputerName.Substring($env:Computername.Length - 3,3) % 2) -eq 1) {
                            $VMHost = $env:ComputerName
                        } Else {
                            $VMHost = $env:ComputerName.Substring(0,$env:ComputerName.Length - 3) + ($env:ComputerName.Substring($env:Computername.Length - 3,3) - 1)
                        }
                    }
                    "~CLEven" {
                        If (($env:ComputerName.Substring($env:Computername.Length - 3,3) % 2) -eq 1) {
                            $VMHost = $env:ComputerName.Substring(0,$env:ComputerName.Length - 3) + ([int]$env:ComputerName.Substring($env:Computername.Length - 3,3) + 1)
                        } Else {
                            $VMHost = $env:ComputerName
                        }
                    }
                    "~CLA" {
                        $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "A"
                    }
                    "~CLB" {
                        $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "B"
                    }
                    "~CLC" {
                        $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "C"
                    }
                    "~CLD" {
                        $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "D"
                    }
                    "~CLE" {
                        $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "E"
                    }
                }
            }
            Write-Host "  VM$i - $VMName on $VMHost"
            If (!(Get-VMHost -ComputerName $VMHost -ErrorAction SilentlyContinue)) {
                $CreateVM = $false
                Write-Host "    Host $VMHost does not exist" -ForegroundColor Red
            } Else {
                $VMHostOS = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $VMHost).Version
                If (($VMGen -eq "2") -and ($VMHostOS -ne "6.3.9600")) {
                    $CreateVM = $false
                    Write-Host "    Host $VMHost does not support Generation 2 VMs" -ForegroundColor Red

                }
            }

            # Check resources on VM host only if the host exists
            If ($CreateVM) {
                # Get OS disk
                $OSDisk = Get-Value -Count $i -Value "OSDisk.Parent"
                If ($OSDisk.Contains("\\")) {
                    $OSDiskUNC = $OSDisk
                } Else {    
                    $OSDiskUNC = "\\" + $VMHost + "\" + $OSDisk.Replace(":","$")
                }
                $VMFolder = Get-Value -Count $i -Value "VMFolder"
                If ($VMFolder.Contains("\\")) {
                    $VMFolderUNC = $VMFolder
                } Else {    
                    $VMFolderUNC = "\\" + $VMHost + "\" + $VMFolder.Replace(":","$")
                }
                $VHDFolder = (Get-Value -Count $i -Value "VHDFolder") + "\" + $VMName + "\Virtual Hard Disks"
                If ($VHDFolder.Contains("\\")) {
                    $VHDFolderUNC = $VHDFolder
                } Else {    
                    $VHDFolderUNC = "\\" + $VMHost + "\" + $VHDFolder.Replace(":","$")
                }
                $SharedVHDXFolder = (Get-Value -Count $i -Value "SharedVHDXFolder")
                $OSVHDFormat = $OSDisk.Split(".")[$OSDisk.Split(".").Count - 1]
                If (!(Test-Path $OSDiskUNC)) {
                    $CreateVM = $false
                    Write-Host "    OS parent disk $OSDisk does not exist" -ForegroundColor Red

                }
                # Get pagefile disk

                $PagefileDisk = Get-Value -Count $i -Value "PagefileDisk"

                If (($PagefileDisk -ne $null) -and ($PagefileDisk -ne "")) {
                    If ($PagefileDisk.Contains("\\")) {
                        $PagefileDiskUNC = $PagefileDisk
                    } Else {    
                        $PagefileDiskUNC = "\\" + $VMHost + "\" + $PagefileDisk.Replace(":","$")
                    }
                    If (!(Test-Path $PagefileDiskUNC)) {
                        $CreateVM = $false
                        Write-Host "    Pagefile parent disk $PagefileDisk does not exist" -ForegroundColor Red
                    }
                }

                #region - VM Switch Configuration
            	$VMSwitch = Get-Value -Count $i -Value "NetworkAdapter.VirtualSwitch"  
				$VMSwitchType = Get-Value -Count $i -Value "NetworkAdapter.VirtualSwitchType"
				# If VirtualSwitchType is not define, set INTERNAL as the default
				if($VMSwitchType -eq $Null){$VMSwitchType="Internal"}
                # Check for Switch and create if not found
       			if(!(Get-VMSwitch -Name $VMSwitch -ComputerName $VMHost -ErrorAction 'SilentlyContinue'))
       			{
        			try 
            		{
						Write-Host -ForegroundColor 'Cyan' "    Creating Virtual Switch named $VMSwitch of type $VMSwitchType..."
						New-VMSwitch -Name $VMSwitch -SwitchType $VMSwitchType -Notes "Virtual Switch" -ErrorAction 'Stop' -ComputerName $VMHost
						Write-Host -ForegroundColor 'Cyan' "    Virtual Switch $VMSwitch created"                     
           			}
           			catch [system.exception]
					{
						Write-Host -ForegroundColor 'Red' "Error: $($_.Exception.Message)"
						Exit
					}
            	}
       			else
        		{
        			Write-Host -ForegroundColor 'Yellow' "    Virtual Switch $VMSwitch exists. Skipping." 
       			}
				#endregion
		   }

            # Check resources to be created do not already exist
            If ($CreateVM) {

                # Check the VM does not already exist
                If (Get-VM -Name $VMName -ComputerName $VMHost -ErrorAction SilentlyContinue) {
                    $CreateVM = $false
                    Write-Host "    VM already exists" -ForegroundColor Red
                }

                # Check the OS disk does not already exist
                If (Test-Path "$VHDFolderUNC\$VMName.$OSVHDFormat") {
                    $CreateVM = $false
                    Write-Host "    Disk $VHDFolder\$VMName.$OSVHDFormat already exists" -ForegroundColor Red
                }

                # Check the pagefile disk does not already exist
                If (($PagefileDisk -ne $null) -and ($PagefileDisk -ne "")) {

                    $PagefileVHDFormat = $PagefileDisk.Split(".")[$PagefileDisk.Split(".").Count - 1]
                    $PagefileVHDName = $VMName + "_" + [char](68 + $DataDrive) + "1"
                    If (Test-Path "$VHDFolderUNC\$PagefileVHDName.$PagefileVHDFormat") {
                        $CreateVM = $false
                        Write-Host "    Disk $VHDFolder\$PagefileVHDName.$PagefileVHDFormat already exists" -ForegroundColor Red
                    }
                }
            }

            # Create
            If ($CreateVM) {

                # Create the VM
                Write-Host "    Creating Generation $VMGen VM - $VMName"
                If ($VMGen -eq "2") {
                    New-VM -Name $VMName -ComputerName $VMHost -Generation $VMGen -Path $VMFolder -NoVHD | Out-Null
                } Else {
                    New-VM -Name $VMName -ComputerName $VMHost -Path $VMFolder -NoVHD | Out-Null
                }

                # Set processors
                $Processor = Get-Value -Count $i -Value "Processor"
                Write-Host "    Setting processors to $Processor"
                Set-VMProcessor -VMName $VMName -ComputerName $VMHost -Count $Processor

                # Set memory
                If (((Get-Value -Count $i -Value "Memory").GetType().FullName -eq "System.String") -or ((Get-Value -Count $i -Value "Memory.Minimum") -eq (Get-Value -Count $i -Value "Memory.Maximum"))) {
                    If ((Get-Value -Count $i -Value "Memory").GetType().FullName -eq "System.String") {
                        [Int64]$Memory = Get-Value -Count $i -Value "Memory"
                    }
                    If ((Get-Value -Count $i -Value "Memory.Minimum") -eq (Get-Value -Count $i -Value "Memory.Maximum")) {
                        [Int64]$Memory = Get-Value -Count $i -Value "Memory.Maximum"
                    }
                    Write-Host "    Setting memory to $Memory`MB"
                    $Memory = $Memory * 1024 * 1024
                    Set-VMMemory -VMName $VMName -ComputerName $VMHost -DynamicMemoryEnabled $false -StartupBytes $Memory
                } Else {
                    [Int64]$StartupMemory = Get-Value -Count $i -Value "Memory.Startup"
                    [Int64]$MinimumMemory = Get-Value -Count $i -Value "Memory.Minimum"
                    [Int64]$MaximumMemory = Get-Value -Count $i -Value "Memory.Maximum"
                    [Int64]$MemoryBuffer = Get-Value -Count $i -Value "Memory.Buffer"
                    Write-Host "    Setting memory to startup $StartupMemory`MB, minimum $MinimumMemory`MB, maximum $MaximumMemory`MB, buffer $MemoryBuffer`%"
                    $StartupMemory = $StartupMemory * 1024 * 1024
                    $MinimumMemory = $MinimumMemory * 1024 * 1024
                    $MaximumMemory = $MaximumMemory * 1024 * 1024
                    Set-VMMemory -VMName $VMName -ComputerName $VMHost -DynamicMemoryEnabled $true -StartupBytes $StartupMemory -MinimumBytes $MinimumMemory -MaximumBytes $MaximumMemory -Buffer $MemoryBuffer
                }

                # Set network adapter
                Remove-VMNetworkAdapter -VMName $VMName -ComputerName $VMHost
                $MAC = Get-Value -Count $i -Value "NetworkAdapter.MAC"
                $NICIdentifier = Get-Value -Count $i -Value "NetworkAdapter.Identifier"
                If ($NICIdentifier -eq $null) {$NICIdentifier = "Ethernet"}
                $MACAddressSpoofing = Get-Value -Count $i -Value "NetworkAdapter.MACAddressSpoofing"
                If ($MACAddressSpoofing -eq $null) {$MACAddressSpoofing = "False"}
                $VLANID = Get-Value -Count $i -Value "NetworkAdapter.VLANID"
                If ($VLANID -eq $null) {$VLANID = "False"}
                If (($MAC -eq $null) -or ($MAC -eq "") -or ($MAC -eq "Dynamic")) {
                    Write-Host "    Adding network adapter $NICIdentifier with dynamic MAC on $VMSwitch"
                    Add-VMNetworkAdapter -VMName $VMName -ComputerName $VMHost -DynamicMACAddress -SwitchName $VMSwitch
                } Else {
                    If ($MAC.GetType().FullName -eq "System.String") {
                        $MAC = Get-Value -Count $i -Value "NetworkAdapter.MAC"
                    } Else {
                        $MACSuffix = ($AutoMACSequence + $AutoMACCount)
                        If ($MACSuffix -lt 16) {
                            $MAC = $AutoMACPrefix + "0" + [Convert]::ToString($MACSuffix,16)
                        } Else {
                            $MAC = $AutoMACPrefix + [Convert]::ToString($MACSuffix,16)
                        }
                        $AutoMACCount ++
                    }
                    Write-Host "    Adding network adapter $NICIdentifier with MAC $MAC on $VMSwitch"
                    Add-VMNetworkAdapter -VMName $VMName -ComputerName $VMHost -StaticMACAddress $MAC -SwitchName $VMSwitch
                }
                If ($MACAddressSpoofing -eq "True") {
                    Set-VMNetworkAdapter -VMName $VMName -ComputerName $VMHost -MacAddressSpoofing On
                }
                If ($VLANID -ne "False") {
                    Set-VMNetworkAdapterVLan -VMName $VMName -ComputerName $VMHost –Access –VLANID $VLANID
                }

                # Set guest services
                $GuestServices = Get-Value -Count $i -Value "GuestServices"
                If ($GuestServices -eq $null) {$GuestServices = "False"}
                If (($VMHostOS -eq "6.3.9600") -and ($GuestServices -eq "True")) {
                    Write-Host "    Enabling guest services"
                    Enable-VMIntegrationService -VMName $VMName -ComputerName $VMHost -Name 'Guest Service Interface'
                }

                # Set startup
                $AutoStartAction = Get-Value -Count $i -Value "AutoStart.Action"
                $AutoStartDelay = Get-Value -Count $i -Value "AutoStart.Delay"
                $AutoStop = Get-Value -Count $i -Value "AutoStop"
                If ($AutoStop -eq $null) {$AutoStop = "Save"}
                Write-Host "    Setting automatic start to `"$AutoStartAction`", delay to $AutoStartDelay and automatic stop to `"$AutoStop`""
                Set-VM -VMName $VMName -ComputerName $VMHost -AutomaticStartAction $AutoStartAction
                Set-VM -VMName $VMName -ComputerName $VMHost -AutomaticStartDelay $AutoStartDelay
                Set-VM -VMName $VMName -ComputerName $VMHost -AutomaticStopAction $AutoStop

                # Set DVD
                $DVD = Get-Value -Count $i -Value "DVD"
                If ($DVD -ne "True") {
                    If ($VMGen -eq "1") {
                        Write-Host "    Removing DVD"
                        Remove-VMDVDDrive -VMName $VMName -ComputerName $VMHost -ControllerNumber 1 -ControllerLocation 0
                    }
                } Else {
                    If ($VMGen -eq "2") {
                        Write-Host "    Adding DVD"
                        If (($PagefileDisk -ne $null) -and ($PagefileDisk -ne "")) {
                            Add-VMDVDDrive -VMName $VMName -ComputerName $VMHost -ControllerNumber 0 -ControllerLocation 2
                        } ELse {
                            Add-VMDVDDrive -VMName $VMName -ComputerName $VMHost -ControllerNumber 0 -ControllerLocation 1
                        }
                        $DataDisk++
                    }
                    $DataDrive++
                }

                # Export for Build
                If ($Mode -eq "Build") {
                    Write-Host "    Exporting"
                    Export-VM -VMName $VMName -ComputerName $VMHost -Path "$VMFolder\!Import"
                    Remove-Item -Path "$VMFolderUNC\!Import\$VMName\Snapshots"
                    Remove-Item -Path "$VMFolderUNC\!Import\$VMName\Virtual Hard Disks"
                }

                # Set OS disk
                Switch (Get-Value -Count $i -Value "OSDisk.Type") {
                    "Differencing" {
                        Write-Host "    Creating differencing disk $VHDFolder\$VMName.$OSVHDFormat"
                        New-VHD -ComputerName $VMHost -Path "$VHDFolder\$VMName.$OSVHDFormat" -ParentPath $OSDisk | Out-Null
                    }
                    "Copy" {
                        Write-Host "    Copying disk $OSDisk to $VHDFolder\$VMName.$OSVHDFormat"
                        If (!(Test-Path $VHDFolderUNC)) {New-Item -Path $VHDFolderUNC -ItemType Directory | Out-Null}
                        Copy-Item -Path $OSDiskUNC -Destination "$VHDFolderUNC\$VMName.$OSVHDFormat"
                    }
                }
                If ($VMGen -eq "2") {
                    $CT = "SCSI"
                    $DataDisk++
                } Else {
                    $CT = "IDE"
                }
                Write-Host "    Attaching disk $VHDFolder\$VMName.$OSVHDFormat to $CT 0:0"
                Add-VMHardDiskDrive -VMName $VMName -ComputerName $VMHost -ControllerType $CT -ControllerNumber 0 -ControllerLocation 0 -Path "$VHDFolder\$VMName.$OSVHDFormat"

                If ($VMGen -eq "2") {

                    Set-VMFirmware -VMName $VMName -ComputerName $VMHost -FirstBootDevice (Get-VMHardDiskDrive $VMName -ComputerName $VMHost -ControllerLocation 0 -ControllerNumber 0)
                }

                # Set pagefile disk
                If (($PagefileDisk -ne $null) -and ($PagefileDisk -ne "")) {
                    $DataDrive++
                    Write-Host "    Copying disk $PagefileDisk to $VHDFolder\$PagefileVHDName.$PagefileVHDFormat"

                    Copy-Item -Path $PagefileDiskUNC -Destination "$VHDFolderUNC\$PagefileVHDName.$PagefileVHDFormat"
                    If ($VMGen -eq "2") {
                        $DataDisk++
                        $DiskPrepStart = 1
                        $DiskPrepCount++
                    } Else {
                        $DiskPrepStart = 2

                    }
                    Write-Host "    Attaching disk $VHDFolder\$PagefileVHDName.$PagefileVHDFormat to $CT 0:1"

                    Add-VMHardDiskDrive -VMName $VMName -ComputerName $VMHost -ControllerType $CT -ControllerNumber 0 -ControllerLocation 1 -Path "$VHDFolder\$PagefileVHDName.$PagefileVHDFormat"

                } Else {
                    $DiskPrepStart = 1
                }

                # Set data disks
                $DataDisks = Get-Value -Count $i -Value "DataDisks"

                If (($DataDisks -ne $null) -and ($DataDisks -ne "")) {

                    $DataDisks | ForEach-Object {
                        $DataDiskCount = $_.Count

                        $DataDiskFormat = $_.Format
                        [int64]$DataDiskSizeGB = $_.Size
                        $DataDiskSize = $DataDiskSizeGB * 1024 * 1024 * 1024
                        For ($j = 1; $j -le $DataDiskCount; $j++) {
                            $DataDiskName = $VMName + "_" + [char](68 + $DataDrive) + "1"

                            Write-Host "    Creating $DataDiskSizeGB`GB data disk $VHDFolder\$DataDiskName.$DataDiskFormat"
                            New-VHD -ComputerName $VMHost -Path "$VHDFolder\$DataDiskName.$DataDiskFormat" -Dynamic -SizeBytes $DataDiskSize | Out-Null
                            Write-Host "    Attaching disk $VHDFolder\$DataDiskName.$DataDiskFormat to SCSI 0:$DataDisk"

                            Add-VMHardDiskDrive -VMName $VMName -ComputerName $VMHost -ControllerType SCSI -ControllerNumber 0 -ControllerLocation $DataDisk -Path "$VHDFolder\$DataDiskName.$DataDiskFormat"
                            $DataDrive++
                            $DataDisk++
                            $DiskPrepCount++
                        }
                    }
                }

				# Set Shared data disks
				$SharedDataDrive = $DataDrive
				$SharedDataDisk = $DataDisk
                $SharedDataDisks = Get-Value -Count $i -Value "SharedDataDisks"
                $SharedDiskPrepCount = 0
                If (($SharedDataDisks -ne $null) -and ($SharedDataDisks -ne "")) {


                    $SharedDataDisks | ForEach-Object {
                        $SharedDataDiskCount = $_.Count
                        $SharedDataDiskFormat = $_.Format

                        [int64]$SharedDataDiskSizeGB = $_.Size
                        $SharedDataDiskSize = $SharedDataDiskSizeGB * 1024 * 1024 * 1024
                        For ($j = 1; $j -le $SharedDataDiskCount; $j++) {
							If ($j -eq 1) {
								$SharedDataDiskName = $_.Prefix + "Witness" + "_" + [char](68 + $SharedDataDrive) + "1"
								$SharedDataDiskSize = 2 * 1024 * 1024 * 1024
							} else {
								$SharedDataDiskName = $_.Prefix + "_" + [char](68 + $SharedDataDrive) + "1"
								$SharedDataDiskSize = $SharedDataDiskSizeGB * 1024 * 1024 * 1024
							}
							If (!(Test-Path -Path "$SharedVHDXFolder\$SharedDataDiskName.$SharedDataDiskFormat")) {


								Write-Host "    Creating $SharedDataDiskSizeGB`GB data disk $SharedVHDXFolder\$SharedDataDiskName.$SharedDataDiskFormat"
								New-VHD -ComputerName $VMHost -Path "$SharedVHDXFolder\$SharedDataDiskName.$SharedDataDiskFormat" -Dynamic -SizeBytes $SharedDataDiskSize | Out-Null

								$DiskPrepCount++
							}
                            Write-Host "    Attaching disk $SharedVHDXFolder\$SharedDataDiskName.$SharedDataDiskFormat to SCSI 0:$SharedDataDisk"
                            Add-VMHardDiskDrive -VMName $VMName -ComputerName $VMHost -ControllerType SCSI -ControllerNumber 0 -ControllerLocation $SharedDataDisk -Path "$SharedVHDXFolder\$SharedDataDiskName.$SharedDataDiskFormat" -ShareVirtualDisk
                            $SharedDataDrive++
                            $SharedDataDisk++
                            
                        }
                    }
                }

                # Get TimeZone
                $TimeZone = Get-Value -Count $i -Value "TimeZone"
                If ($TimeZone -eq $null) {$TimeZone = "Pacific Standard Time"}

                # Mount OS disk to insert unattend files
                $Drive = $null
                While ($Drive -eq $null) {
                    Write-Host "    Mounting $VHDFolder\$VMName.$OSVHDFormat"
                    Start-Sleep 1
                    $Drives = (Mount-VHD -Path "$VHDFolderUNC\$VMName.$OSVHDFormat" -ErrorAction SilentlyContinue -PassThru | Get-Disk | Get-Partition).DriveLetter
                    If ($Drives.Count -gt 1) {
                        $LargestDrive = 0
                        For ($d = 0; $d -lt $Drives.Count; $d++) {

                            If (($Drives[$d] -ne [char]0) -and ((Get-Partition -DriveLetter $Drives[$d]).Size -gt $LargestDrive)) {
                                $Drive = $Drives[$d]
                                $LargestDrive = (Get-Partition -DriveLetter $Drives[$d]).Size

                            }
                        }
                    } Else {
                        $Drive = $Drives
                    }
                    If ($Drive -ne $null) {
                        Write-Host "      $VHDFolder\$VMName.$OSVHDFormat mounted as $Drive`:"
                        While (!(Test-Path "$Drive`:\")) {Start-Sleep 1}
                        $JoinDomain = Get-Value -Count $i -Value "JoinDomain.Domain"
                        $JoinDomainDomain = Get-Value -Count $i -Value "JoinDomain.Credentials.Domain"
                        $JoinDomainPassword = Get-Value -Count $i -Value "JoinDomain.Credentials.Password"
                        $JoinDomainUsername = Get-Value -Count $i -Value "JoinDomain.Credentials.Username"
                        $AdministratorPassword = Get-Value -Count $i -Value "AdministratorPassword"
                        $WindowsProductKey = Get-Value -Count $i -Value "WindowsProductKey"

                        Write-Host "      Inserting unattend.xml"
                        If ((($Domain -eq $null) -or ($DomainExisting)) -or ((($Domain -ne $null) -and !($DomainExisting)) -and ($i -ne 1))) {
                            Write-Host "        Join domain: $JoinDomain"
                            Write-Host "        Join domain credentials: $JoinDomainDomain\$JoinDomainUsername"
                            Write-Host "        Installer service account: $InstallerServiceAccountDomain\$InstallerServiceAccountUsername"
                            $JoinDomainOrganizationalUnit = Get-Value -Count $i -Value "JoinDomain.OrganizationalUnit"
                            $JoinDomainOrganizationalUnitFull = ""
                            If (($JoinDomainOrganizationalUnit -ne $null) -and ($JoinDomainOrganizationalUnit -ne "")) {
                                $JoinDomainOrganizationalUnit.Split(".") | ForEach-Object {
                                    $JoinDomainOrganizationalUnitFull = $JoinDomainOrganizationalUnitFull + "OU=$_,"
                                }
                                $JoinDomain.Split(".") | ForEach-Object {
                                    $JoinDomainOrganizationalUnitFull = $JoinDomainOrganizationalUnitFull + "DC=$_,"
                                }
                                $JoinDomainOrganizationalUnitFull = $JoinDomainOrganizationalUnitFull.Substring(0,$JoinDomainOrganizationalUnitFull.Length - 1)
                                Write-Host "        Organizational unit: $JoinDomainOrganizationalUnitFull"
                            }
                        }
@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>$VMName</ComputerName>
            <RegisteredOrganization></RegisteredOrganization>
            <RegisteredOwner></RegisteredOwner>
"@ | Out-File "$Drive`:\unattend.xml" -Encoding ASCII
                        If ($WindowsProductKey) {
@"
            <ProductKey>$WindowsProductKey</ProductKey>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        }
@"
        </component>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        $IP = Get-Value -Count $i -Value "NetworkAdapter.IP"
                        If (!(($IP -eq $null) -or ($IP -eq "") -or ($IP -eq "DHCP"))) {
                            $IPAddress = Get-Value -Count $i -Value "NetworkAdapter.IP.Address"
                            If ($IPAddress -eq $null) {
                                $IPAddress = $AutoIPPrefix + ($AutoIPSequence + $AutoIPCount)
                                $AutoIPCount ++
                            }
                            $IPMask = Get-Value -Count $i -Value "NetworkAdapter.IP.Mask"
                            Write-Host "        IP address: $IPAddress/$IPMask"
                            $IPGateway = Get-Value -Count $i -Value "NetworkAdapter.IP.Gateway"
                            Write-Host "        IP gateway: $IPGateway"
@"
        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                    </Ipv4Settings>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$IPAddress/$IPMask</IpAddress>
                    </UnicastIpAddresses>
                    <Identifier>$NICIdentifier</Identifier>
                    <Routes>
                        <Route wcm:action="add">
                            <Identifier>1</Identifier>
                            <Prefix>0.0.0.0/0</Prefix>
                            <NextHopAddress>$IPGateway</NextHopAddress>
                        </Route>
                    </Routes>
                </Interface>
            </Interfaces>
        </component>
        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                            $DNSCount = 0
                            If ((($Domain -ne $null) -and !($DomainExisting)) -and ($i -eq 1)) {
                                $DNS = @("127.0.0.1")
                            } Else {
                                $DNS = Get-Value -Count $i -Value "NetworkAdapter.IP.DNS"
                            }
                            $DNS | ForEach-Object {
                                $DNSCount++
                                Write-Host "        DNS address: $_"
@"
                        <IpAddress wcm:action="add" wcm:keyValue="$DNSCount">$_</IpAddress>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                            }
@"
                    </DNSServerSearchOrder>
                    <Identifier>$NICIdentifier</Identifier>
                </Interface>
            </Interfaces>
        </component>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        }
                        If ((($Domain -eq $null) -or ($DomainExisting)) -or ((($Domain -ne $null) -and !($DomainExisting)) -and ($i -ne 1))) {
@"
        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Identification>
                <Credentials>
                    <Domain>$JoinDomainDomain</Domain>
                    <Password>$JoinDomainPassword</Password>
                    <Username>$JoinDomainUsername</Username>
                </Credentials>
                <JoinDomain>$JoinDomain</JoinDomain>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                            If ($JoinDomainOrganizationalUnitFull -ne "") {
@"
                <MachineObjectOU>$JoinDomainOrganizationalUnitFull</MachineObjectOU>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                            }
@"
            </Identification>
        </component>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        }   
@"
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAuthentication>0</UserAuthentication>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        If ((($Domain -ne $null) -and !($DomainExisting)) -and ($i -eq 1)) 
						{

@"
            <AutoLogon>
                <Password>
                    <Value>$AdministratorPassword</Value>
                    <PlainText>true</PlainText>
                </Password>
                <LogonCount>1</LogonCount>
                <Username>Administrator</Username>
                <Enabled>true</Enabled>
            </AutoLogon>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        } ElseIf ((($Setup -ne $null) -and (Test-Path "$Setup\$VMName")) -or ($Mode -eq "Build")) 
						{

@"
            <AutoLogon>
                <Password>
                    <Value>$InstallerServiceAccountPassword</Value>
                    <PlainText>true</PlainText>
                </Password>
                <LogonCount>1</LogonCount>
                <Username>$InstallerServiceAccount</Username>
                <Enabled>true</Enabled>
            </AutoLogon>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        }
@"
            <TimeZone>$TimeZone</TimeZone>
            <UserAccounts>
                <DomainAccounts>
                    <DomainAccountList wcm:action="add">
                        <Domain>$InstallerServiceAccountDomain</Domain>
                        <DomainAccount wcm:action="add">
                            <Name>$InstallerServiceAccountUsername</Name>
                            <Group>Administrators</Group>
                        </DomainAccount>

"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        If (($Domain -eq $null) -or ($DomainExisting)) 
						{
                            If (($env:UserDomain -eq $InstallerServiceAccountDomain) -and ($env:Username -ne $InstallerServiceAccountUsername))
							{


@"
                        <DomainAccount wcm:action="add">
                            <Name>$env:Username</Name>
                            <Group>Administrators</Group>
                        </DomainAccount>
						
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                            } Else 
							{
                                If ($env:UserDomain -ne $InstallerServiceAccountDomain) 
								{


@"
                    </DomainAccountList>
					<DomainAccountList wcm:action="add">
                        <Domain>$env:UserDomain</Domain>
                        <DomainAccount wcm:action="add">
                            <Name>$env:Username</Name>
                            <Group>Administrators</Group>
                        </DomainAccount>
                    
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                                }
                            }
                        } 
@"
                </DomainAccountList>
				</DomainAccounts>
                <AdministratorPassword>
                    <Value>$AdministratorPassword</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <RegisteredOrganization></RegisteredOrganization>
            <RegisteredOwner></RegisteredOwner>
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <SkipMachineOOBE>true</SkipMachineOOBE>
            </OOBE>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        If (((($Domain -ne $null) -and !($DomainExisting)) -and ($i -eq 1)) -or ((($Setup -ne $null) -and (Test-Path "$Setup\$VMName")) -or ($Mode -eq "Build"))) {
@"
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <RequiresUserInput>false</RequiresUserInput>
                    <CommandLine>C:\Temp\Setup.bat</CommandLine>
                    <Order>1</Order>
                </SynchronousCommand>
            </FirstLogonCommands>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        }
@"
        </component>
    </settings>
</unattend>
"@ | Out-File "$Drive`:\unattend.xml" -Append -Encoding ASCII
                        Write-Host "      Inserting SetupComplete.cmd"
                        If (!(Test-Path "$Drive`:\Windows\Setup\Scripts")) {New-Item -Path "$Drive`:\Windows\Setup\Scripts" -ItemType Directory | Out-Null}
@"
@echo off
if exist %SystemDrive%\unattend.xml del %SystemDrive%\unattend.xml
reg add HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /t REG_SZ /d "Unrestricted" /f

ipconfig.exe /registerdns
powershell.exe -command %WinDir%\Setup\Scripts\SetupComplete.ps1
"@ | Out-File "$Drive`:\Windows\Setup\Scripts\SetupComplete.cmd" -Encoding ASCII
                        Write-Host "      Inserting SetupComplete.ps1"
@"
If ((Get-WmiObject -Class Win32_OperatingSystem).BuildNumber -le 7601) {Enable-PSRemoting -Force}
"@ | Out-File "$Drive`:\Windows\Setup\Scripts\SetupComplete.ps1" -Encoding ASCII
                        If (($DVD -eq "True") -and ($PagefileDisk -ne $null) -and ($PagefileDisk -ne "")) {

@"
`$DVD = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter = 'D:'"
Set-WmiInstance -InputObject `$DVD -Arguments @{DriveLetter="E:"}
"@ | Out-File "$Drive`:\Windows\Setup\Scripts\SetupComplete.ps1" -Encoding ASCII -Append

                        }
@"

For (`$a = $DiskPrepStart; `$a -lt ($DiskPrepStart + $DiskPrepCount); `$a++) {
    Get-Disk | Where-Object {`$_.Number -eq `$a} | Set-Disk -IsOffline `$false
    Get-Disk | Where-Object {`$_.Number -eq `$a} | Initialize-Disk -PartitionStyle MBR
    New-Partition -DiskNumber `$a -UseMaximumSize -AssignDriveLetter
    While ((Get-Partition -DiskNumber `$a -PartitionNumber 1).Type -ne "IFS") {            
        Get-Partition -DiskNumber `$a | Format-Volume -FileSystem NTFS -Confirm:`$false
    }
}
Get-NetFirewallRule -Group "@FirewallAPI.dll,-30267" -Direction Inbound | Where-Object {($_.Enabled -eq "False") -and ($_.Profile -ne "Public")} | ForEach-Object {Enable-NetFirewallRule -Name $_.Name}
Get-NetFirewallRule -Group "@FirewallAPI.dll,-28502" -Direction Inbound | Set-NetFirewallRule -Profile Domain -Enabled True
Get-NetFirewallRule -Group "@FirewallAPI.dll,-34251" -Direction Inbound | Set-NetFirewallRule -Profile Domain -Enabled True

Remove-Item "$env:WinDir\Setup\Scripts\SetupComplete.cmd"
Remove-Item "$env:WinDir\Setup\Scripts\SetupComplete.ps1"
If (!(Test-Path "C:\Temp\$VMName.ps1")) {Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Virtual Machine\Auto" -Name "`$env:ComputerName" -Value 1}
"@ | Out-File "$Drive`:\Windows\Setup\Scripts\SetupComplete.ps1" -Encoding ASCII -Append
                        If ((($Domain -ne $null) -and !($DomainExisting)) -and ($i -eq 1)) {
                            Write-Host "      Inserting Autologon Setup"
                            If (!(Test-Path "$Drive`:\Temp")) {New-Item -Path "$Drive`:\Temp" -ItemType Directory | Out-Null}
@"
@echo off
C:
cd\
mode con cols=120
if exist Temp\%ComputerName%.bat call Temp\%ComputerName%.bat
if not exist Temp\Setup.ps1 logoff.exe
if exist Temp\Setup.ps1 powershell.exe -command Temp\Setup.ps1
"@ | Out-File "$Drive`:\Temp\Setup.bat" -Encoding ASCII
                            If (($Mode -eq "Build") -and !(Test-Path "$Drive`:\Temp\X-$VMName.ps1")) {
@"
`$IPAddress = '$IPAddress'
`$IPMask = '$IPMask'
`$IPGateway = '$IPGateway'
`$DNS = '$DNS'
"@ | Out-File "$Drive`:\Temp\X-$VMName.ps1" -Encoding ASCII
                            }
                            Write-Host "      Inserting $VMName Startup"
                            $DomainShort = $Domain.Split(".")[0]
@"
Start-transcript -literalpath C:\temp\Setup.log -append
`$Computer = `$env:ComputerName

`$Step = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft" -Name "VMCreate" -ErrorAction SilentlyContinue).VMCreate
If (`$Step -eq `$null) {`$Step = "Step1"}

function Get-RegValue (`$Server,`$Value) {
    try {`$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', `$Server)} catch {`$reg = `$null}
    If (`$reg -ne `$Null) {
        `$regKey= `$reg.OpenSubKey("SOFTWARE\\Microsoft\\Virtual Machine\\Auto")           
        If (`$regKey -ne `$Null) {
            If (`$regkey.GetValue(`$Value) -eq 1) {
                return `$True
            } Else {
                return `$False
            }
        }
    }
}

Function Get-Value (`$Value,`$Count) {
    If ((Invoke-Expression ("```$Variable.Installer.VMs.VM | Where-Object {```$_.Count -eq ```$Count} | ForEach-Object {```$_.`$Value}")) -ne `$null) {
        Invoke-Expression ("Return ```$Variable.Installer.VMs.VM | Where-Object {```$_.Count -eq ```$Count} | ForEach-Object {```$_.`$Value}")
    } Else {
        Invoke-Expression ("Return ```$Variable.Installer.VMs.Default.`$Value")
    }
}

Function Set-ScriptVariable (`$Name,`$Value) {
    Invoke-Expression ("```$Script:" + `$Name + " = ```"" + `$Value + "```"")
    If ((`$Name.Contains("ServiceAccount")) -and !(`$Name.Contains("Password")) -and (`$Value -ne "")) {
        Invoke-Expression ("```$Script:" + `$Name + "Domain = ```"" + `$Value.Split("\")[0] + "```"")
        Invoke-Expression ("```$Script:" + `$Name + "Username = ```"" + `$Value.Split("\")[1] + "```"")
    }
}

Switch (`$Step) {
    "Step1" {
        # Prepare for step 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft" -Name "VMCreate" -Value "Step2"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "VMCreate" -Value "C:\Temp\Setup.bat"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Value 1

        # Install Active Directory and reboot
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
        `$password = ConvertTo-SecureString -AsPlainText -String "$AdministratorPassword" -Force
        Import-Module ADDSDeployment
        `$DatabasePath = "C:\Windows\NTDS"
        `$LogPath = "C:\Windows\NTDS"
        `$SysvolPath = "C:\Windows\SYSVOL"
        If (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")}) {
"@ | Out-File "$Drive`:\Temp\Setup.ps1" -Encoding ASCII
                            If ($VMGen -eq "2") {
                                If (($PagefileDisk -ne $null) -and ($PagefileDisk -ne "")) {
@"
            `$DatabasePath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[1].Number)[2].DriveLetter + ":\Windows\NTDS"
            `$LogPath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[1].Number)[2].DriveLetter + ":\Windows\NTDS"
            `$SysvolPath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[1].Number)[2].DriveLetter + ":\Windows\SYSVOL"
            If ((Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")}).Count -gt 1) {
                `$LogPath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[2].Number)[2].DriveLetter + ":\Windows\NTDS"
            }
"@ | Out-File "$Drive`:\Temp\Setup.ps1" -Encoding ASCII -Append
                                } Else {
@"
            `$DatabasePath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[0].Number)[2].DriveLetter + ":\Windows\NTDS"
            `$LogPath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[0].Number)[2].DriveLetter + ":\Windows\NTDS"
            `$SysvolPath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[0].Number)[2].DriveLetter + ":\Windows\SYSVOL"
            If ((Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")}).Count -gt 1) {
                `$LogPath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[1].Number)[2].DriveLetter + ":\Windows\NTDS"
            }
"@ | Out-File "$Drive`:\Temp\Setup.ps1" -Encoding ASCII -Append
                                }
                            } Else {
@"
            `$DatabasePath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[0].Number)[2].DriveLetter + ":\Windows\NTDS"
            `$LogPath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[0].Number)[2].DriveLetter + ":\Windows\NTDS"
            `$SysvolPath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[0].Number)[2].DriveLetter + ":\Windows\SYSVOL"
            If ((Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")}).Count -gt 1) {
                `$LogPath = (Get-Partition -DiskNumber (Get-Disk | Where-Object {(`$_.BusType -eq "SCSI") -or (`$_.BusType -eq "SAS")} | Sort-Object Number)[1].Number)[2].DriveLetter + ":\Windows\NTDS"
            }
"@ | Out-File "$Drive`:\Temp\Setup.ps1" -Encoding ASCII -Append
                            }
@"
        }
        Install-ADDSForest -DomainName "$Domain" -ForestMode "Win2012" -DomainMode "Win2012" -InstallDns:`$true -SafeModeAdministratorPassword `$password -CreateDnsDelegation:`$false -DomainNetbiosName "$DomainShort" -DatabasePath `$DatabasePath -LogPath `$LogPath -SysvolPath `$SysvolPath -NoRebootOnCompletion:`$false -Force:`$true
    }
    "Step2" {
        # Prepare for step 3
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft" -Name "VMCreate" -Value "Step3"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "VMCreate" -Value "C:\Temp\Setup.bat"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Value 1

        Import-Module ActiveDirectory
        `$Workflow = [XML] (Get-Content "C:\Temp\Workflow.xml")
        If (Test-Path "`C:\Temp\Extender*.xml") {
            Get-ChildItem -Path "`C:\Temp\Extender*.xml" | ForEach-Object {
                `$ExtenderFile = `$_.Name
                `$Extender = [XML] (Get-Content "C:\Temp\`$ExtenderFile")
                `$Extender.Installer.ServerFeatures | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderServerFeaturesOSVersion = `$_.OSVersion
                    `$_.Group | Where-Object {`$_ -ne `$null} | ForEach-Object {
                        `$ExtenderServerFeaturesGroup = `$_.Name
                        `$_.ServerFeature | Where-Object {`$_ -ne `$null} | ForEach-Object {
                            `$ExtenderServerFeature = `$_
                            If (!(`$Workflow.Installer.ServerFeatures | Where-Object {`$_.OSVersion -eq `$ExtenderServerFeaturesOSVersion} | ForEach-Object {`$_.Group} | Where-Object {`$_.Name -eq `$ExtenderServerFeaturesGroup} | ForEach-Object {`$_.ServerFeature} | Where-Object {`$_.Name -eq `$ExtenderServerFeature.Name})) {
                                (`$Workflow.Installer.ServerFeatures | Where-Object {`$_.OSVersion -eq `$ExtenderServerFeaturesOSVersion} | ForEach-Object {`$_.Group} | Where-Object {`$_.Name -eq `$ExtenderServerFeaturesGroup}).AppendChild(`$Workflow.ImportNode(`$ExtenderServerFeature,`$true)) | Out-Null
                            }
                        }
                    }
                }
                `$Extender.Installer.Installables.Installable | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderInstallable = `$_
                    If (!(`$Workflow.Installer.Installables.Installable | Where-Object {`$_.Name -eq `$ExtenderInstallable.Name})) {
                        `$Workflow.Installer.Installables.AppendChild(`$Workflow.ImportNode(`$ExtenderInstallable,`$true)) | Out-Null
                    }
                }
                `$Extender.Installer.Components.Component | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderComponent = `$_
                    If (!(`$Workflow.Installer.Components.Component | Where-Object {`$_.Name -eq `$ExtenderComponent.Name})) {
                        `$Workflow.Installer.Components.AppendChild(`$Workflow.ImportNode(`$ExtenderComponent,`$true)) | Out-Null
                    }
                }
                `$Extender.Installer.SQL.SQL | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderSQL = `$_
                    If (!(`$Workflow.Installer.SQL.SQL | Where-Object {`$_.Version -eq `$ExtenderSQL.Version})) {
                        `$Workflow.Installer.SQL.AppendChild(`$Workflow.ImportNode(`$ExtenderSQL,`$true)) | Out-Null
                    }
                }
                `$Extender.Installer.Roles.Role | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderRole = `$_
                    If (!(`$Workflow.Installer.Role.Role | Where-Object {`$_.Name -eq `$ExtenderRole.Name})) {
                        `$Workflow.Installer.Roles.AppendChild(`$Workflow.ImportNode(`$ExtenderRole,`$true)) | Out-Null
                    }
                }
                `$Extender.Installer.Integrations.Integration | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderIntegration = `$_
                    If (!(`$Workflow.Installer.Integrations.Integration | Where-Object {`$_.Name -eq `$ExtenderIntegration.Name})) {
                        `$Workflow.Installer.Integrations.AppendChild(`$Workflow.ImportNode(`$ExtenderIntegration,`$true)) | Out-Null
                    }
                }
            }
        }
        `$Variable = [XML] (Get-Content "C:\Temp\Variable.xml")
        `$Domain = `$Variable.Installer.VMs.Domain.Name
        `$ADRoot = (Get-ADRootDSE).DefaultNamingContext
        # Create OUs
        `$OUs = @(`$Variable.Installer.VMs.Default.JoinDomain.OrganizationalUnit)
        `$OUs += `$Variable.Installer.VMs.Domain.ServiceAccountOU
        `$OUs += `$Variable.Installer.VMs.Domain.GroupOU
		`$OUs += `$Variable.Installer.VMs.Domain.UserOU				
        `$OUs += `$Variable.Installer.VMs.VM | ForEach-Object {`$_.JoinDomain.OrganizationalUnit}
        `$OUs = `$OUs | Sort-Object -Unique
        `$OUs | ForEach-Object {
            `$OU = `$_.Split(".")
            `$TryOU = `$ADRoot
            `$OURoot = `$ADRoot
            For (`$i = `$OU.Count - 1; `$i -ge 0; `$i--) {
                `$TryOU = "OU=" + `$OU[`$i] + "," + `$TryOU
                Try {Get-ADOrganizationalUnit -Identity "`$TryOU"} Catch {
                    New-ADOrganizationalUnit -Name `$OU[`$i] -Path "`$OURoot" -ProtectedFromAccidentalDeletion `$true
                }
                `$OURoot = `$TryOU
            }
        }

        # Create service accounts
        `$ServiceAccountOU = `$Variable.Installer.VMs.Domain.ServiceAccountOU
        If (`$ServiceAccountOU -ne `$null) {
            `$ServiceAccountOU = `$ServiceAccountOU.Split(".")
            `$ServiceAccountOUPath = `$ADRoot
            For (`$i = `$ServiceAccountOU.Count - 1; `$i -ge 0; `$i--) {
                `$ServiceAccountOUPath = "OU=" + `$ServiceAccountOU[`$i] + "," + `$ServiceAccountOUPath
            }
        } Else {
            `$ServiceAccountOUPath = "CN=Users," + `$ADRoot
        }
        `$ServiceAccount = `$Variable.Installer.VMs.Default.JoinDomain.Credentials.Username
        `$ServiceAccountPassword = `$Variable.Installer.VMs.Default.JoinDomain.Credentials.Password
        try {Get-ADUser -Identity `$ServiceAccount} catch {
            `$SecurePassword = ConvertTo-SecureString `$ServiceAccountPassword -AsPlainText -Force
            New-ADUser -Name `$ServiceAccount -AccountPassword `$SecurePassword -CannotChangePassword `$true -PasswordNeverExpires `$true -Path `$ServiceAccountOUPath -Enabled `$true
            `$JDSID = (Get-ADUser -Identity "`$ServiceAccount").SID
            `$acl = Get-Acl -Path "AD:`$ADRoot"
            `$ComputerGuid = New-Object Guid bf967a86-0de6-11d0-a285-00aa003049e2
            `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$JDSID,"CreateChild","Allow",`$ComputerGuid,"All"
            `$acl.AddAccessRule(`$ace)
            `$PermissionGuid = New-Object Guid 4c164200-20c0-11d0-a768-00aa006e0529
            `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$JDSID,"ReadProperty,WriteProperty","Allow",`$PermissionGuid,"Descendents",`$ComputerGuid
            `$acl.AddAccessRule(`$ace)
            `$PermissionGuid = New-Object Guid f3a64788-5306-11d1-a9c5-0000f80367c1
            `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$JDSID,"Self","Allow",`$PermissionGuid,"Descendents",`$ComputerGuid
            `$acl.AddAccessRule(`$ace)
            `$PermissionGuid = New-Object Guid 72e39547-7b18-11d1-adef-00c04fd8d5cd
            `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$JDSID,"Self","Allow",`$PermissionGuid,"Descendents",`$ComputerGuid
            `$acl.AddAccessRule(`$ace)
            `$PermissionGuid = New-Object Guid 00299570-246d-11d0-a768-00aa006e0529
            `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$JDSID,"ExtendedRight","Allow",`$PermissionGuid,"Descendents",`$ComputerGuid
            `$acl.AddAccessRule(`$ace)
            Set-Acl -Path "AD:`$ADRoot" -AclObject `$acl
        }   
        `$Variable.Installer.Variable | Where-Object {`$_.Name -eq "InstallerServiceAccount"} | ForEach-Object {
            `$ServiceAccountName = `$_.Name
            `$ServiceAccount = (`$_.Value).Split("\")[1]
            `$ServiceAccountPassword = `$Variable.Installer.Variable | Where-Object {`$_.Name -eq "`$ServiceAccountName```Password"} | ForEach-Object {`$_.Value}
            try {Get-ADUser -Identity `$ServiceAccount} catch {
                `$SecurePassword = ConvertTo-SecureString `$ServiceAccountPassword -AsPlainText -Force
                New-ADUser -Name `$ServiceAccount -AccountPassword `$SecurePassword -CannotChangePassword `$true -PasswordNeverExpires `$true -Path `$ServiceAccountOUPath -Enabled `$true
            }
            `$AdminGroup = (Get-WMIObject Win32_Group -filter "LocalAccount=True AND SID='S-1-5-32-544'").Name

            Add-ADGroupMember -Identity `$AdminGroup -Members `$ServiceAccount
        }
        `$Variable.Installer.Variable | Where-Object {`$_.Name.Contains("ServiceAccount") -and !(`$_.Name.Contains("Password"))} | ForEach-Object {
            `$ServiceAccountName = `$_.Name
            `$ServiceAccount = (`$_.Value).Split("\")[1]
            `$ServiceAccountPassword = `$Variable.Installer.Variable | Where-Object {`$_.Name -eq "`$ServiceAccountName```Password"} | ForEach-Object {`$_.Value}
            try {Get-ADUser -Identity `$ServiceAccount} catch {
                `$SecurePassword = ConvertTo-SecureString `$ServiceAccountPassword -AsPlainText -Force
                New-ADUser -Name `$ServiceAccount -AccountPassword `$SecurePassword -CannotChangePassword `$true -PasswordNeverExpires `$true -Path `$ServiceAccountOUPath -Enabled `$true
            }   
        }
        `$Variable.Installer.Components.Component | ForEach-Object {`$_.Variable} | Where-Object {(`$_ -ne `$null) -and `$_.Name.Contains("ServiceAccount") -and !(`$_.Name.Contains("Password"))} | ForEach-Object {
            `$ServiceAccountName = `$_.Name
            `$ServiceAccount = (`$_.Value).Split("\")[1]
            `$ServiceAccountPassword = `$Variable.Installer.Components.Component.Variable | Where-Object {`$_.Name -eq "`$ServiceAccountName```Password"} | ForEach-Object {`$_.Value}
            try {Get-ADUser -Identity `$ServiceAccount} catch {
                `$SecurePassword = ConvertTo-SecureString `$ServiceAccountPassword -AsPlainText -Force
                New-ADUser -Name `$ServiceAccount -AccountPassword `$SecurePassword -CannotChangePassword `$true -PasswordNeverExpires `$true -Path `$ServiceAccountOUPath -Enabled `$true
            }   
        }
        `$Variable.Installer.SQL.Instance | ForEach-Object {
            `$Server = `$_.Server
            `$Instance = `$_.Instance
            `$Variable.Installer.SQL.Instance | Where-Object {(`$_.Server -eq `$Server) -and (`$_.Instance -eq `$Instance)} | ForEach-Object {`$_.Variable} | Where-Object {(`$_ -ne `$null) -and `$_.Name.Contains("ServiceAccount") -and !(`$_.Name.Contains("Password"))} | ForEach-Object {
                `$ServiceAccountName = `$_.Name
                `$ServiceAccount = (`$_.Value).Split("\")[1]
                `$ServiceAccountPassword = `$Variable.Installer.SQL.Instance | Where-Object {(`$_.Server -eq `$Server) -and (`$_.Instance -eq `$Instance)} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -eq "`$ServiceAccountName```Password"} | ForEach-Object {`$_.Value}
                try {Get-ADUser -Identity `$ServiceAccount} catch {
                    `$SecurePassword = ConvertTo-SecureString `$ServiceAccountPassword -AsPlainText -Force
                    New-ADUser -Name `$ServiceAccount -AccountPassword `$SecurePassword -CannotChangePassword `$true -PasswordNeverExpires `$true -Path `$ServiceAccountOUPath -Enabled `$true
                    # SQL SPN Permissions
                    `$acl = Get-ACL -Path "AD:CN=`$ServiceAccount,`$ServiceAccountOUPath"
                    `$Self = [System.Security.Principal.SecurityIdentifier]'S-1-5-10'
                    `$SPNGuid = New-Object Guid f3a64788-5306-11d1-a9c5-0000f80367c1
                    `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$Self,"ReadProperty,WriteProperty","Allow",`$SPNGuid,"None"
                    `$acl.AddAccessRule(`$ace)
                    Set-ACL -Path "AD:CN=`$ServiceAccount,`$ServiceAccountOUPath" -AclObject `$acl
                }   
            }
        }
        `$Variable.Installer.SQL.Cluster | ForEach-Object {
            `$Cluster = `$_.Cluster
            `$Variable.Installer.SQL.Cluster | Where-Object {`$_.Cluster -eq `$Cluster} | ForEach-Object {`$_.Variable} | Where-Object {(`$_ -ne `$null) -and `$_.Name.Contains("ServiceAccount") -and !(`$_.Name.Contains("Password"))} | ForEach-Object {
                `$ServiceAccountName = `$_.Name
                `$ServiceAccount = (`$_.Value).Split("\")[1]
                `$ServiceAccountPassword = `$Variable.Installer.SQL.Cluster | Where-Object {`$_.Cluster -eq `$Cluster} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -eq "`$ServiceAccountName```Password"} | ForEach-Object {`$_.Value}
                try {Get-ADUser -Identity `$ServiceAccount} catch {
                    `$SecurePassword = ConvertTo-SecureString `$ServiceAccountPassword -AsPlainText -Force
                    New-ADUser -Name `$ServiceAccount -AccountPassword `$SecurePassword -CannotChangePassword `$true -PasswordNeverExpires `$true -Path `$ServiceAccountOUPath -Enabled `$true
                    # SQL SPN Permissions
                    `$acl = Get-ACL -Path "AD:CN=`$ServiceAccount,`$ServiceAccountOUPath"
                    `$Self = [System.Security.Principal.SecurityIdentifier]'S-1-5-10'
                    `$SPNGuid = New-Object Guid f3a64788-5306-11d1-a9c5-0000f80367c1
                    `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `$Self,"ReadProperty,WriteProperty","Allow",`$SPNGuid,"None"
                    `$acl.AddAccessRule(`$ace)
                    Set-ACL -Path "AD:CN=`$ServiceAccount,`$ServiceAccountOUPath" -AclObject `$acl
                }   
            }
        }

        # Create groups
        `$GroupOU = `$Variable.Installer.VMs.Domain.GroupOU
        If (`$GroupOU -ne `$null) {
            `$GroupOU = `$GroupOU.Split(".")
            `$GroupOUPath = `$ADRoot
            For (`$i = `$GroupOU.Count - 1; `$i -ge 0; `$i--) {
                `$GroupOUPath = "OU=" + `$GroupOU[`$i] + "," + `$GroupOUPath
            }
        } Else {
            `$GroupOUPath = "CN=Users," + `$ADRoot
        }
        `$Components = `$Workflow.Installer.Components.Component | ForEach-Object {`$_.Name}
        `$Components | ForEach-Object {
            `$Component = `$_
            If (`$Workflow.Installer.Components.Component | Where-Object {`$_.Name -eq `$Component} | ForEach-Object {`$_.Variable | Where-Object {`$_.Principal -eq "True"}}) {
                `$CR = `$False
                `$ADSearch = New-Object System.DirectoryServices.DirectorySearcher
                `$Workflow.Installer.Roles.Role | Where-Object {`$_.Component -eq `$Component} | ForEach-Object {
                    `$Role = `$_.Name
                    `$Variable.Installer.Roles.Role | Where-Object {`$_.Name -eq `$Role} | ForEach-Object {
                        If (`$CR -eq `$False) {
                            `$CR = `$True
                            `$Workflow.Installer.Components.Component | Where-Object {`$_.Name -eq `$Component} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -ne `$null} | ForEach-Object {
                                Set-ScriptVariable -Name `$_.Name -Value `$_.Value
                            }
                            `$Variable.Installer.Components.Component | Where-Object {`$_.Name -eq `$Component} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -ne `$null} | ForEach-Object {
                                Set-ScriptVariable -Name `$_.Name -Value `$_.Value
                            }
                            `$Workflow.Installer.Components.Component | Where-Object {`$_.Name -eq `$Component} | ForEach-Object {`$_.Variable | Where-Object {`$_.Principal -eq "True"}} | ForEach-Object {
                                `$Principal = `$_.Name
                                If ((Get-Item "Variable:`$Principal").Value) {
                                    `$PrincipalValidate = `$false
                                    `$PrincipalValue = (Get-Item "Variable:`$Principal").Value
                                    `$PrincipalValueUserGroup = `$PrincipalValue.Split("\")[1]
                                    `$ADSearch.Filter = ("(&(objectCategory=user)(CN=`$PrincipalValueUserGroup))")
                                    If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                                    `$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483644)(CN=`$PrincipalValueUserGroup))")
                                    If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                                    `$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483646)(CN=`$PrincipalValueUserGroup))")
                                    If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                                    `$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483640)(CN=`$PrincipalValueUserGroup))")
                                    If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                                    If (!(`$PrincipalValidate)) {
                                        New-ADGroup -Name `$PrincipalValueUserGroup -Path `$GroupOUPath -GroupScope Global -GroupCategory Security
                                        Add-ADGroupMember -Identity `$PrincipalValueUserGroup -Members `$env:Username
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        `$Variable.Installer.SQL.Instance | ForEach-Object {
            `$Server = `$_.Server
            `$Instance = `$_.Instance
            `$SQLVersion = `$_.Version
            `$Workflow.Installer.SQL.SQL | Where-Object {`$_.Version -eq `$SQLVersion} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Principal -eq "True"} | ForEach-Object {
                `$Principal = `$_.Name
                `$Workflow.Installer.SQL.SQL | Where-Object {`$_.Version -eq `$SQLVersion} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -ne `$null} | ForEach-Object {
                    Set-ScriptVariable -Name `$_.Name -Value `$_.Value
                }
                `$Variable.Installer.SQL.Server | Where-Object {(`$_.Server -eq `$Server)} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -ne `$null} | ForEach-Object {
                    Set-ScriptVariable -Name `$_.Name -Value `$_.Value
                }
                `$Variable.Installer.SQL.Instance | Where-Object {(`$_.Server -eq `$Server) -and (`$_.Instance -eq `$Instance)} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -ne `$null} | ForEach-Object {
                    Set-ScriptVariable -Name `$_.Name -Value `$_.Value
                }
                `$PrincipalValidate = `$false
                `$PrincipalValue = (Get-Item "Variable:`$Principal").Value
                `$PrincipalValueUserGroup = `$PrincipalValue.Split("\")[1]
                `$ADSearch.Filter = ("(&(objectCategory=user)(CN=`$PrincipalValueUserGroup))")
                If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                `$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483644)(CN=`$PrincipalValueUserGroup))")
                If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                `$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483646)(CN=`$PrincipalValueUserGroup))")
                If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                `$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483640)(CN=`$PrincipalValueUserGroup))")
                If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                If (!(`$PrincipalValidate)) {
                    New-ADGroup -Name `$PrincipalValueUserGroup -Path `$GroupOUPath -GroupScope Global -GroupCategory Security
                    Add-ADGroupMember -Identity `$PrincipalValueUserGroup -Members `$env:Username
                }
            }
        }
        `$Variable.Installer.SQL.Cluster | ForEach-Object {
            `$Cluster = `$_.Cluster
            `$SQLVersion = `$_.Version
            `$Workflow.Installer.SQL.SQL | Where-Object {`$_.Version -eq `$SQLVersion} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Principal -eq "True"} | ForEach-Object {
                `$Principal = `$_.Name
                `$Workflow.Installer.SQL.SQL | Where-Object {`$_.Version -eq `$SQLVersion} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -ne `$null} | ForEach-Object {
                    Set-ScriptVariable -Name `$_.Name -Value `$_.Value
                }
                `$Variable.Installer.SQL.Server | Where-Object {(`$_.Server -eq `$Server)} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -ne `$null} | ForEach-Object {
                    Set-ScriptVariable -Name `$_.Name -Value `$_.Value
                }
                `$Variable.Installer.SQL.Cluster | Where-Object {`$_.Cluster -eq `$Cluster} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -ne `$null} | ForEach-Object {
                    Set-ScriptVariable -Name `$_.Name -Value `$_.Value
                }
                `$PrincipalValidate = `$false
                `$PrincipalValue = (Get-Item "Variable:`$Principal").Value
                `$PrincipalValueUserGroup = `$PrincipalValue.Split("\")[1]
                `$ADSearch.Filter = ("(&(objectCategory=user)(CN=`$PrincipalValueUserGroup))")
                If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                `$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483644)(CN=`$PrincipalValueUserGroup))")
                If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                `$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483646)(CN=`$PrincipalValueUserGroup))")
                If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                `$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483640)(CN=`$PrincipalValueUserGroup))")
                If (`$ADSearch.FindOne()) {`$PrincipalValidate = `$true}
                If (!(`$PrincipalValidate)) {
                    New-ADGroup -Name `$PrincipalValueUserGroup -Path `$GroupOUPath -GroupScope Global -GroupCategory Security
                    Add-ADGroupMember -Identity `$PrincipalValueUserGroup -Members `$env:Username
                }
            }
        }
        
        # Create NLB DNS entries
        `$Components = `$Workflow.Installer.Roles.Role | Where-Object {`$_.Validation.NLB -eq "True"} | ForEach-Object {`$_.Component} | Sort-Object -Unique
        `$Components | ForEach-Object {
            `$Component = `$_
            `$Workflow.Installer.Components.Component | Where-Object {`$_.Name -eq `$Component} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -ne `$null} | ForEach-Object {
                Set-ScriptVariable -Name `$_.Name -Value `$_.Value
            }
            `$Variable.Installer.Components.Component | Where-Object {`$_.Name -eq `$Component} | ForEach-Object {`$_.Variable} | Where-Object {`$_.Name -ne `$null} | ForEach-Object {
                Set-ScriptVariable -Name `$_.Name -Value `$_.Value
            }
        }
        `$Roles = @(`$Variable.Installer.Roles.Role)
        `$Roles | ForEach-Object {
            `$Role = `$_.Name
            If ((Invoke-Expression ("``$" + `$Role.Replace(" ","") + "NLBConfig")) -eq "True") {
                `$FullName = Invoke-Expression ("``$" + `$Role.Replace(" ","") + "NLBName")
                `$IP = Invoke-Expression ("``$" + `$Role.Replace(" ","") + "NLBIPv4")
                `$Name = `$FullName.Split(".")[0]
                `$Zone = `$FullName.SubString(`$Name.Length + 1)
                If (!(Get-DnsServerResourceRecord -ZoneName `$Zone -Name `$Name -RRType A -ErrorAction SilentlyContinue)) {
                    Add-DnsServerResourceRecordA -ZoneName `$Zone -Name `$Name -IPv4Address `$IP
                }
            } Else {
                If (((Invoke-Expression ("``$" + `$Role.Replace(" ","") + "NLBName")) -ne `$null) -and ((Invoke-Expression ("``$" + `$Role.Replace(" ","") + "NLBName")) -ne "")) {
                    `$FullName = Invoke-Expression ("``$" + `$Role.Replace(" ","") + "NLBName")
                    `$Name = `$FullName.Split(".")[0]
                    `$Zone = `$FullName.SubString(`$Name.Length + 1)
                    `$Variable.Installer.Roles.Role | Where-Object {`$_.Name -eq `$Role} | ForEach-Object {
                        `$RoleServer = `$_.Server
                    }
                    If (!(Get-DnsServerResourceRecord -ZoneName `$Zone -Name `$Name -RRType CName -ErrorAction SilentlyContinue)) {
                        Add-DnsServerResourceRecordCName -ZoneName `$Zone -Name `$Name -HostNameAlias `$RoleServer
                    }
                }
            }
        }

        # Reboot for group membership
        Restart-Computer -Force
    }
    "Step3" {
        `$Workflow = [XML] (Get-Content "C:\Temp\Workflow.xml")
        If (Test-Path "`C:\Temp\Extender*.xml") {
            Get-ChildItem -Path "`C:\Temp\Extender*.xml" | ForEach-Object {
                `$ExtenderFile = `$_.Name
                `$Extender = [XML] (Get-Content "C:\Temp\`$ExtenderFile")
                `$Extender.Installer.ServerFeatures | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderServerFeaturesOSVersion = `$_.OSVersion
                    `$_.Group | Where-Object {`$_ -ne `$null} | ForEach-Object {
                        `$ExtenderServerFeaturesGroup = `$_.Name
                        `$_.ServerFeature | Where-Object {`$_ -ne `$null} | ForEach-Object {
                            `$ExtenderServerFeature = `$_
                            If (!(`$Workflow.Installer.ServerFeatures | Where-Object {`$_.OSVersion -eq `$ExtenderServerFeaturesOSVersion} | ForEach-Object {`$_.Group} | Where-Object {`$_.Name -eq `$ExtenderServerFeaturesGroup} | ForEach-Object {`$_.ServerFeature} | Where-Object {`$_.Name -eq `$ExtenderServerFeature.Name})) {
                                (`$Workflow.Installer.ServerFeatures | Where-Object {`$_.OSVersion -eq `$ExtenderServerFeaturesOSVersion} | ForEach-Object {`$_.Group} | Where-Object {`$_.Name -eq `$ExtenderServerFeaturesGroup}).AppendChild(`$Workflow.ImportNode(`$ExtenderServerFeature,`$true)) | Out-Null
                            }
                        }
                    }
                }
                `$Extender.Installer.Installables.Installable | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderInstallable = `$_
                    If (!(`$Workflow.Installer.Installables.Installable | Where-Object {`$_.Name -eq `$ExtenderInstallable.Name})) {
                        `$Workflow.Installer.Installables.AppendChild(`$Workflow.ImportNode(`$ExtenderInstallable,`$true)) | Out-Null
                    }
                }
                `$Extender.Installer.Components.Component | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderComponent = `$_
                    If (!(`$Workflow.Installer.Components.Component | Where-Object {`$_.Name -eq `$ExtenderComponent.Name})) {
                        `$Workflow.Installer.Components.AppendChild(`$Workflow.ImportNode(`$ExtenderComponent,`$true)) | Out-Null
                    }
                }
                `$Extender.Installer.SQL.SQL | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderSQL = `$_
                    If (!(`$Workflow.Installer.SQL.SQL | Where-Object {`$_.Version -eq `$ExtenderSQL.Version})) {
                        `$Workflow.Installer.SQL.AppendChild(`$Workflow.ImportNode(`$ExtenderSQL,`$true)) | Out-Null
                    }
                }
                `$Extender.Installer.Roles.Role | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderRole = `$_
                    If (!(`$Workflow.Installer.Role.Role | Where-Object {`$_.Name -eq `$ExtenderRole.Name})) {
                        `$Workflow.Installer.Roles.AppendChild(`$Workflow.ImportNode(`$ExtenderRole,`$true)) | Out-Null
                    }
                }
                `$Extender.Installer.Integrations.Integration | Where-Object {`$_ -ne `$null} | ForEach-Object {
                    `$ExtenderIntegration = `$_
                    If (!(`$Workflow.Installer.Integrations.Integration | Where-Object {`$_.Name -eq `$ExtenderIntegration.Name})) {
                        `$Workflow.Installer.Integrations.AppendChild(`$Workflow.ImportNode(`$ExtenderIntegration,`$true)) | Out-Null
                    }
                }
            }
        }
        `$Variable = [XML] (Get-Content "C:\Temp\Variable.xml")
        `$Domain = `$Variable.Installer.VMs.Domain.Name

        If (Get-WindowsFeature Server-Gui-Shell | Where-Object {`$_.Installed}) {Install-WindowsFeature RSAT-ADDS-Tools}

        If (Test-Path "C:\Temp\$VMName.ps1") {C:\Temp\$VMName.ps1}

        # AD done!
        Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Virtual Machine\Auto" -Name "$VMName-AD" -Value 1

        # Wait for VMs
        # Get unique servers
        `$Servers = @(`$Variable.Installer.Roles.Role | Where-Object {(`$_.Existing -ne "True") -and (`$_.SQLCluster -ne "True")} | Sort-Object {`$_.Server} -Unique | ForEach-Object {`$_.Server})
        `$SQLClusters = @(`$Variable.Installer.Roles.Role | Where-Object {(`$_.Existing -ne "True") -and (`$_.SQLCluster -eq "True")} | ForEach-Object {`$_.Server})
        `$SQLClusters | ForEach-Object {
            `$SQLCluster = `$_
            `$SQLClusterNodes = `$Variable.Installer.SQL.Cluster | Where-Object {`$_.Cluster -eq `$SQLCluster} | ForEach-Object {`$_.Node.Server}
            `$Servers += `$SQLClusterNodes
        }
        `$Servers | Sort-Object -Unique | ForEach-Object {
            `$VMName = `$_.split(".")[0]
            If ((`$VMName -ne "TMG") -and (`$VMName -ne `$computer)) {
                Write-Host " Verifying access to `$VMName"
                Write-Host "  Remote registry... " -NoNewLine
                While (!(Get-RegValue -Server `$VMName -Value `$VMName)) {Start-Sleep 1}
                Write-Host "Ready" -ForegroundColor Green
                Write-Host "  DNS Resolution... " -NoNewLine
                While (!(Resolve-DNSName -Name "`$VMName.`$Domain" -ErrorAction SilentlyContinue)) {
                    Invoke-Command -ComputerName `$VMName -ScriptBlock {ipconfig.exe /registerdns | Out-Null}
                    Start-Sleep 15
                }
                Write-Host "Ready" -ForegroundColor Green
            }
        }

"@ | Out-File "$Drive`:\Temp\Setup.ps1" -Encoding ASCII -Append
                            $InstallerSwitches = "-MaxStage $MaxStage"
                            If ($Mode -eq "Build") {$InstallerSwitches = $InstallerSwitches + " -Mode Build"}
                            If ($SkipValidation) {$InstallerSwitches = $InstallerSwitches + " -SkipValidation All"}
@"
        C:\Temp\Installer.ps1 -Path C:\Temp $InstallerSwitches
"@ | Out-File "$Drive`:\Temp\Setup.ps1" -Append -Encoding ASCII
@"
        `$Success = `$true
        If (Get-ChildItem -Path "`$env:LocalAppData\Installer\*.log" -ErrorAction SilentlyContinue) {
            Get-ChildItem -Path "`$env:LocalAppData\Installer\*.log" | Where-Object {`$_.Name -ne 'Installer.log'} | ForEach-Object {
                If ((Get-Content -Path `$_ -Tail 2)[0].substring(0,11) -ne 'Cleaning up') {`$Success = `$false}
            }
        } Else {
            `$Success = `$false
        }

        If (`$Success) {
            # Cleanup
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft" -Name "VMCreate"
            If (Test-Path 'C:\Temp\X-$VMName.ps1') {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "VMCreate" -Value "C:\Temp\Setup.bat"
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Value 1
            }
            Remove-Item 'C:\Temp\Setup.bat'
            Add-Content -Path 'C:\Temp\Setup.bat' -Value '@echo off' -Encoding ascii
            Add-Content -Path 'C:\Temp\Setup.bat' -Value 'C:' -Encoding ascii
            Add-Content -Path 'C:\Temp\Setup.bat' -Value 'cd\' -Encoding ascii
            Add-Content -Path 'C:\Temp\Setup.bat' -Value 'if exist Temp\%ComputerName%.bat call Temp\%ComputerName%.bat' -Encoding ascii
            Add-Content -Path 'C:\Temp\Setup.bat' -Value 'if not exist Temp\%ComputerName%.ps1 logoff.exe' -Encoding ascii
            Add-Content -Path 'C:\Temp\Setup.bat' -Value 'if exist Temp\%ComputerName%.ps1 powershell.exe -command Temp\%ComputerName%.ps1' -Encoding ascii
            Add-Content -Path 'C:\Temp\Setup.bat' -Value 'if not exist Temp\block.txt echo y|reg add "HKLM\SOFTWARE\Microsoft\Virtual Machine\Auto" /v %ComputerName% /t REG_DWORD /d 1' -Encoding ascii
            If ('$MaxStage' -eq '7Integration') {
                Get-ChildItem -Path 'C:\Temp' -Recurse -ErrorAction SilentlyContinue | Where-Object {`$_.Name -ne "Setup.bat"} | ForEach-Object {`$_.Attributes = 'Normal'}
                Get-ChildItem -Path 'C:\Temp' -Recurse -Hidden -ErrorAction SilentlyContinue | Where-Object {`$_.Name -ne "Setup.bat"} | ForEach-Object {`$_.Attributes = 'Normal'}
                Get-ChildItem -Path 'C:\Temp' -ErrorAction SilentlyContinue | Where-Object {(`$_.Name -ne "Setup.bat") -and (`$_.Name -ne "X-`$Computer.ps1") -and !((`$_.Name.Length -eq 36) -and (`$_.Name.Substring(8,1) -eq "-") -and (`$_.Name.Substring(13,1) -eq "-") -and (`$_.Name.Substring(18,1) -eq "-") -and (`$_.Name.Substring(23,1) -eq "-"))} | Remove-Item -Recurse
            }
            If (Test-Path "C:\Temp\X-`$Computer.ps1") {Rename-Item -Path "C:\Temp\X-`$Computer.ps1" "`$Computer.ps1"}
        } Else {
            `$x = `$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            `$x = `$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            `$x = `$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }

    }
}
Stop-transcript
"@ | Out-File "$Drive`:\Temp\Setup.ps1" -Append -Encoding ASCII
                            Write-Host "      Copying Installer.ps1"
                            Copy-Item -Path "$Path\Installer.ps1" -Destination "$Drive`:\Temp"
                            Write-Host "      Copying Workflow.xml"
                            Copy-Item -Path "$Path\Workflow.xml" -Destination "$Drive`:\Temp"
                            If (Test-Path "$Path\Extender*.xml") {
                                Get-ChildItem -Path "$Path\Extender*.xml" | ForEach-Object {
                                    $ExtenderFile = $_.Name
                                    Write-Host "      Copying $ExtenderFile"
                                    Copy-Item -Path "$Path\$ExtenderFile" -Destination "$Drive`:\Temp"
                                }
                            }
                            Write-Host "      Copying Variable.xml"
                            Copy-Item -Path "$Path\Variable.xml" -Destination "$Drive`:\Temp"
                            Write-Host "    Preparing sources"
                            # Get Installables
                            $Servers = @($Variable.Installer.Roles.Role | Where-Object {($_.Existing -ne "True") -and ($_.SQLCluster -ne "True")} | Sort-Object {$_.Server} -Unique | ForEach-Object {$_.Server})
                            $SQLClusters = @($Variable.Installer.Roles.Role | Where-Object {($_.Existing -ne "True") -and ($_.SQLCluster -eq "True")} | ForEach-Object {$_.Server})
                            $SQLClusters | ForEach-Object {
                                $SQLCluster = $_
                                $SQLClusterNodes = $Variable.Installer.SQL.Cluster | Where-Object {$_.Cluster -eq $SQLCluster} | ForEach-Object {$_.Node.Server}
                                $Servers += $SQLClusterNodes
                            }
                            $Servers = $Servers | Sort-Object -Unique
                            $Roles = @($Variable.Installer.Roles.Role)

                            # Get SQL versions
                            $Installables = @("Windows Server 2012 R2","Windows Server 2012")
                            $Servers | ForEach-Object {
                                $Server = $_
                                $Variable.Installer.Roles.Role | Where-Object {($_.Server -eq $Server) -and ($_.Instance -ne $null)} | ForEach-Object {$_.Instance} | Sort-Object -Unique | ForEach-Object {
                                    $Instance = $_
                                    $Variable.Installer.SQL.Instance | Where-Object {($_.Server -eq $Server) -and ($_.Instance -eq $Instance)} | ForEach-Object {
                                        $Installables += $_.Version
                                    }
                                }
                            }

                            # Get roles
                            $MRoles = @()
                            $Servers | ForEach-Object {
                                $Server = $_

                                # Get roles for this server
                                $MRoles += @($Variable.Installer.Roles.Role | Where-Object {$_.Server -eq $Server} | Where-Object {$_.Existing -ne "True"} | ForEach-Object {$_.Name})

                                # Get SQL cluster roles for this server
                                $Variable.Installer.SQL.Cluster | ForEach-Object {
                                    $SQLCluster = $_.Cluster
                                    $_.Node | Where-Object {$_.Server -eq $Server} | ForEach-Object {
                                        $SQLClusterNode = $_.Server
                                        $SQLClusterNodes = $Variable.Installer.Roles.Role | Where-Object {$_.Server -eq $SQLCluster} | ForEach-Object {$_.Name}
                                        $MRoles += $SQLClusterNodes
                                    }
                                }

                                # Get integrations for this server
                                # For each role on this server...
                                $MRoles | ForEach-Object {
                                    $Role = $_
                                    $Integration = $false
                                    # ...find integrations targeted at that role
                                    $Workflow.Installer.Integrations.Integration | Where-Object {$_.Target -eq $Role} | ForEach-Object {
                                        $ThisIntegration = $_.Name
                                        $Integration = $true
                                        # Check that all integration dependencies exist in this deployment
                                        $_.Dependency | ForEach-Object {
                                            $Dependency = $_
                                            If (!($Variable.Installer.Roles.Role | Where-Object {$_.Name -eq $Dependency})) {
                                                $Integration = $false
                                            }
                                        }
                                        If ($Integration) {
                                            $MRoles += $ThisIntegration
                                        }
                                    }
                                }
                            }
                            $MRoles = $MRoles | Sort-Object -Unique

                            # Get installables
                            $MRoles | ForEach-Object {
                                $Role = $_
                                $Workflow.Installer.Roles.Role | Where-Object {$_.Name -eq $Role} | ForEach-Object {
                                    $_.Prerequisites | ForEach-Object {
                                        $_.Prerequisite | ForEach-Object {
                                            $Prerequisite = $_.Name
                                            $Workflow.Installer.Installables.Installable | ForEach-Object {
                                                $InstallableName = $_.Name
                                                If ($_.Install | Where-Object {$_.Name -eq $Prerequisite}) {
                                                    $Installables += $InstallableName
                                                }
                                            }
                                        }
                                    }
                                    $_.Install | ForEach-Object {
                                        $Installables += $_.Installable
                                    }
                                }
                            }
                            $Installables = $Installables | Sort-Object -Unique

                            # Get additional installables
                            $Installables | ForEach-Object {
                                $Installable = $_
                                $Workflow.Installer.Installables.Installable | Where-Object {$_.Name -eq $Installable} | ForEach-Object {
                                    If ($_.AdditionalDownload) {
                                        $_.AdditionalDownload | ForEach-Object {
                                            $Installables += $_
                                        }
                                    }
                                }
                            }
                            $Installables = $Installables | Sort-Object -Unique
                            $SystemDrive = $env:SystemDrive
                            If ($Variable.Installer.Variable | Where-Object {$_.Name -eq "SourcePath"}) {
                                $SourcePath = $Variable.Installer.Variable | Where-Object {$_.Name -eq "SourcePath"} | ForEach-Object {$_.Value}
                            } Else {
                                $SourcePath = $Workflow.Installer.Variable | Where-Object {$_.Name -eq "SourcePath"} | ForEach-Object {$_.Value}
                            }
                            If ($Variable.Installer.Variable | Where-Object {$_.Name -eq "Download"}) {
                                $Download = $Variable.Installer.Variable | Where-Object {$_.Name -eq "Download"} | ForEach-Object {$_.Value}
                            } Else {
                                $Download = $Workflow.Installer.Variable | Where-Object {$_.Name -eq "Download"} | ForEach-Object {$_.Value}
                            }
                            $Installables | ForEach-Object {
                                $SystemDrive = $env:SystemDrive
                                $Installable = $_
                                $InstallableSource = $Workflow.Installer.Installables.Installable | Where-Object {$_.Name -eq $Installable} | ForEach-Object {$_.SourceFolder}
                                If ($InstallableSource -ne $null) {
                                    $Workflow.Installer.Installables.Installable | Where-Object {$_.Name -eq $Installable} | ForEach-Object {
                                        If ($_.Variable) {
                                            $_.Variable | ForEach-Object {
                                                If (Get-Variable $_.Name -ErrorAction SilentlyContinue) {
                                                    Set-Variable -Name $_.Name -Value $_.Value
                                                } Else {        
                                                    New-Variable -Name $_.Name -Value $_.Value
                                                }
                                            }
                                        }
                                    }
                                    $Variable.Installer.Installables.Installable | Where-Object {$_.Name -eq $Installable} | ForEach-Object {
                                        If ($_.Variable) {
                                            $_.Variable | ForEach-Object {
                                                If (Get-Variable $_.Name -ErrorAction SilentlyContinue) {
                                                    Set-Variable -Name $_.Name -Value $_.Value
                                                } Else {        
                                                    New-Variable -Name $_.Name -Value $_.Value
                                                }
                                            }
                                        }
                                    }
                                    $DownloadFolder = Invoke-Expression ($InstallableSource)
                                    Write-Host "      Copying source $Installable"
                                    $SystemDrive = "$Drive`:"
                                    Invoke-Expression("`$SourcePath = `"$SourcePath`"")
                                    Start-Process -FilePath "robocopy.exe" -ArgumentList "$Download\$DownloadFolder $SourcePath\$DownloadFolder /e" -Wait -WindowStyle Hidden
                                }
                            }
                        } ElseIf ((($Setup -ne $null) -and (Test-Path "$Setup\$VMName")) -or ($Mode -eq "Build")) {
                            Write-Host "      Inserting Autologon Setup"
                            If (!(Test-Path "$Drive`:\Temp")) {New-Item -Path "$Drive`:\Temp" -ItemType Directory | Out-Null}
@"
@echo off
C:
cd\
mode con cols=120
if exist Temp\%ComputerName%.bat call Temp\%ComputerName%.bat
if not exist Temp\%ComputerName%.ps1 logoff.exe
if exist Temp\%ComputerName%.ps1 powershell.exe -command Temp\%ComputerName%.ps1
if not exist Temp\block.txt echo y|reg add "HKLM\SOFTWARE\Microsoft\Virtual Machine\Auto" /v %ComputerName% /t REG_DWORD /d 1
"@ | Out-File "$Drive`:\Temp\Setup.bat" -Encoding ASCII
                            If (($Mode -eq "Build") -and !(Test-Path "$Drive`:\Temp\X-$VMName.ps1")) {
@"
`$IPAddress = '$IPAddress'
`$IPMask = '$IPMask'
`$IPGateway = '$IPGateway'
`$DNS = '$DNS'
"@ | Out-File "$Drive`:\Temp\X-$VMName.ps1" -Encoding ASCII
                            }
                            Write-Host "      Copying Variable.xml"
                            Copy-Item -Path "$Path\Variable.xml" -Destination "$Drive`:\Temp"
                        }
                        If (($Setup -ne $null) -and (Test-Path "$Setup\$VMName")) {
							Write-Host "      Copying additional VM scripts"
                            Start-Process -FilePath "robocopy.exe" -ArgumentList "$Setup\$VMName $Drive`:\Temp /e" -Wait -WindowStyle Hidden
                            If (Test-Path "$Setup\$VMName\unattend.xml") {Start-Process -FilePath "robocopy.exe" -ArgumentList "$Setup\$VMName $Drive`:\ unattend.xml /e" -Wait -WindowStyle Hidden}
                        } ElseIf ($Mode -eq "Build") {
@"
`$Computer = `$env:ComputerName
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "VMCreate" -Value "C:\Temp\Setup.bat"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Value 1

# Cleanup
Get-ChildItem -Path 'C:\Temp' -Recurse -ErrorAction SilentlyContinue | Where-Object {`$_.Name -ne "Setup.bat"} | ForEach-Object {`$_.Attributes = 'Normal'}
Get-ChildItem -Path 'C:\Temp' -Recurse -Hidden -ErrorAction SilentlyContinue | Where-Object {`$_.Name -ne "Setup.bat"} | ForEach-Object {`$_.Attributes = 'Normal'}
Get-ChildItem -Path 'C:\Temp' -ErrorAction SilentlyContinue | Where-Object {(`$_.Name -ne "Setup.bat") -and (`$_.Name -ne "X-`$Computer.ps1")} | Remove-Item -Recurse
If (Test-Path "C:\Temp\X-`$Computer.ps1") {Rename-Item -Path "C:\Temp\X-`$Computer.ps1" "`$Computer.ps1"}
"@ | Out-File "$Drive`:\Temp\$VMName.ps1" -Encoding ASCII
                        }
                    }

                    Write-Host "      Dismounting $VHDFolder\$VMName.$OSVHDFormat"
                    Dismount-VHD -Path "$VHDFolderUNC\$VMName.$OSVHDFormat" -ErrorAction SilentlyContinue
                }

				# Start VM if Existing Domain, is domain controller, or AD is up and running

				If (!($DomainExisting)) 
				 {
					
				    $ADVMHost = Get-Value -Count 1 -Value "Host"
					$ADVMName = Get-Value -Count 1 -Value "VMName"
					
					$ADStarted = Get-VMKVP -VMName $ADVMName -VMHost $ADVMHost -KVPName "$ADVMName-AD"
					# Write-Host "       [DEBUG] Active Directory Status $ADStarted" -ForegroundColor Cyan
				}

                If ((($Domain -eq $null) -or ($DomainExisting)) -or ($i -eq 1) -or ($ADStarted -ne $null)) {
                    Write-Host "    Starting $VMName"
                    Start-VM -VMName $VMName -ComputerName $VMHost
                }
            } Else {
                $AutoMACCount++
                $AutoIPCount++
            }

        }
        Write-Host ""
        # Wait for AD then start VMs
        If (($Domain -ne $null) -and !($DomainExisting)) {
            $AutonameCount = 0
            Write-Host "  Waiting for Active Directory"
            $VMHost = Get-Value -Count 1 -Value "Host"
            If ($VMHost.Substring(0,3) -eq "~CL") {
                Switch ($VMHost) {
                    "~CLOdd" {
                        If (($env:ComputerName.Substring($env:Computername.Length - 3,3) % 2) -eq 1) {
                            $VMHost = $env:ComputerName
                        } Else {
                            $VMHost = $env:ComputerName.Substring(0,$env:ComputerName.Length - 3) + ($env:ComputerName.Substring($env:Computername.Length - 3,3) - 1)
                        }
                    }
                    "~CLEven" {
                        If (($env:ComputerName.Substring($env:Computername.Length - 3,3) % 2) -eq 1) {
                            $VMHost = $env:ComputerName.Substring(0,$env:ComputerName.Length - 3) + ([int]$env:ComputerName.Substring($env:Computername.Length - 3,3) + 1)
                        } Else {
                            $VMHost = $env:ComputerName
                        }
                    }
                    "~CLA" {
                        $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "A"
                    }
                    "~CLB" {
                        $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "B"
                    }
                    "~CLC" {
                        $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "C"
                    }
                    "~CLD" {
                        $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "D"
                    }
                    "~CLE" {
                        $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "E"
                    }
                }
            }
            If ((Get-Value -Count 1 -Value "VMName").GetType().FullName -eq "System.String") {
                $VMName = Get-Value -Count 1 -Value "VMName"
            } Else {
                $VMName = $AutonamePrefix + ($AutonameSequence + $AutonameCount).ToString("00")
                $AutonameCount ++
            }
            While (!(Get-VMKVP -VMName $VMName -VMHost $VMHost -KVPName "$VMName-AD")) {Start-Sleep 1}
            For ($i = 2; $i -le $VMCount; $i++) {
                # Get the VM name - specific or autonamed
                If ((Get-Value -Count $i -Value "VMName").GetType().FullName -eq "System.String") {
                    $VMName = Get-Value -Count $i -Value "VMName"
                } Else {
                    $VMName = $AutonamePrefix + ($AutonameSequence + $AutonameCount).ToString("00")
                    $AutonameCount ++
                }
                $VMHost = Get-Value -Count $i -Value "Host"
                If ($VMHost.Substring(0,3) -eq "~CL") {
                    Switch ($VMHost) {
                        "~CLOdd" {
                            If (($env:ComputerName.Substring($env:Computername.Length - 3,3) % 2) -eq 1) {
                                $VMHost = $env:ComputerName
                            } Else {
                                $VMHost = $env:ComputerName.Substring(0,$env:ComputerName.Length - 3) + ($env:ComputerName.Substring($env:Computername.Length - 3,3) - 1)
                            }
                        }
                        "~CLEven" {
                            If (($env:ComputerName.Substring($env:Computername.Length - 3,3) % 2) -eq 1) {
                                $VMHost = $env:ComputerName.Substring(0,$env:ComputerName.Length - 3) + ([int]$env:ComputerName.Substring($env:Computername.Length - 3,3) + 1)
                            } Else {
                                $VMHost = $env:ComputerName
                            }
                        }
                        "~CLA" {
                            $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "A"
                        }
                        "~CLB" {
                            $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "B"
                        }
                        "~CLC" {
                            $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "C"
                        }
                        "~CLD" {
                            $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "D"
                        }
                        "~CLE" {
                            $env:COMPUTERNAME.Substring(0,$env:COMPUTERNAME.Length - 1) + "E"
                        }
                    }
                }

                If ((Get-VM -Name $VMName -ComputerName $VMHost -ErrorAction SilentlyContinue) -and ((Get-VM -Name $VMName -ComputerName $VMHost -ErrorAction SilentlyContinue).State -ne "Running")) {
                    Write-Host "  Starting $VMName"
                    Start-VM -VMName $VMName -ComputerName $VMHost
                }
            }
        }
    }
} Else {
    Write-Host "Hyper-V module not available"
}

Write-Host "`nVMCreator started at: $StartDate"
$Date=Get-Date
Write-Host "VMCreator finished at: $Date"
Write-Host "`nScript execution time in minutes:" 
$TotalTime = $Date - $StartDate
Write-Host $TotalTime.TotalMinutes
# Stop-Transcript if logging is enabled.
If ($EnableLogging)
{
	Stop-Transcript
}



