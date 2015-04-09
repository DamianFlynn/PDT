<# 	
 .NOTES
	Copyright 2014 (c) Microsoft Corporation.  All rights reserved.

	A WSSC CAT Solution Created by Rob Willis
	
	In collaboration with:
	 	PowerShell Deployment Toolkit Team (PDT)
		America Enterprise Services - Azure IaaS Center of Expertise (COE)
		Service Provider Operational Readiness Kit (ORK)
		Datacenter and Cloud Infrastrucutre Services (COE)
               	
	File:		Installer.ps1
	
	Pre-Reqs:	Windows Server 2012 or Windows Server 2012 R2, and Windows PowerShell 4.0	
				
	Version: 	2.65.2.0

	Contributors:    Rob Willis, Robert Larson, Joel Stidley, David McFarlane-Smith, Joze Markic


 .SYNOPSIS
    Installer is part of the PowerShell Deployment Toolkit and is used to deploy the software defined in Variable.xml.
  
 .DESCRIPTION
	This script is used to deploy software defined as part of the PDT deployment process. 
	
	In a greenfield deployment, Installer is automatically run for you. 
	In a non-greenfield deployment, you must run Installer manually after VMCreator and DomainPrep have been run.
  	 		
 .EXAMPLE
	C:\PS> .\Installer.ps1 -Path C:\PDT
	
	Description
	-----------
	This command uses the Variable.xml and Workflow.xml files in the C:\PDT directory to define what is deployed.
	
 .EXAMPLE
	C:\PS> .\Installer.ps1 -ValidateOnly
	
	Description
	-----------
	This command uses the Variable.xml and Workflow.xml files in the local directory to define what is deployed. Only validation will be completed, no changes will be made to the environment.

 .EXAMPLE
	C:\PS> .\Installer.ps1 -SkipValidation ALL
	
	Description
	-----------
	This command uses the Variable.xml and Workflow.xml files in the local directory to define what is deployed. The execution skips all validation stages and immediately starts the installation process.
	
 .PARAMETER Path
	Specifies the path to the Variable.xml, Workflow.xml, Installer.ps1, and any Extender files that will be used.

 .PARAMETER ValidateOnly
	Specifies to only validate the deployment files and configuration; however no deployment steps will be attempted.
	
 .PARAMETER SkipValidation
	Specifies to skip a specific validation process or all of the validation processes and then start the deployment. Valid options are:
	
	* All - Disables: All of the validation group checks.
	* Local - Disables: Checks FQDN, dependencies, role combinations, role instance count, required variables, SQL instances, and installation media.
	* ActiveDirectory - Disables: Checks for service accounts and passwords, security principals, and groups.
	* Remote - Disables: Checks for administrator access to servers, if clusters exist, and that the following are functioning: WinRM, Task Scheduler, credentials policy, operating system version, file access, certificates, and minimum memory
	* RoleCombinations - Disables: Checks for roles and their dependencies are able to be installed on the same host.
	
 .PARAMETER Mode
	Specifies a mode in which to start the installation.

 .PARAMETER MaxStage
	Specifies how much of the deployment that Installer will complete. Valid options are:
	
	* 1Admin – Adds service accounts to local administrator groups
	* 2ServerFeatures – Installs Windows Roles and Features
	* 3SQLClusters – Installs SQL clustered instances
	* 4SQL – Installs SQL standalone instances
	* 5Prereqs – Installs prerequisites
	* 6Roles – Installs roles
	* 7Integration – Completes integration and configuration
	
	Each stage includes the actions of the previous stages.

 .INPUTS
           None.

 .OUTPUTS
           None.

 .LINK
	http://aka.ms/pdt
#>

#region Startup
Param
(
	[Parameter(Mandatory = $false, Position = 0)]
	[String]$Path = (Get-Location),
	
	[Parameter(Mandatory = $false)]
	[Switch]$ValidateOnly = $false,
	
	[Parameter(Mandatory = $false)]
	[ValidateSet("All", "Local", "ActiveDirectory", "Remote", "RoleCombinations", "Media")]$SkipValidation,
	
	[Parameter(Mandatory = $false)]
	[String]$Mode,
	
	[Parameter(Mandatory = $false)]
	[ValidateSet("1Admin", "2ServerFeatures", "3SQLClusters", "4SQL", "5Prereqs", "6Roles", "7Integration")]
	[String]$MaxStage = "7Integration"
)

# Elevate
Write-Host "Checking for elevation... " -NoNewline
$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
if (($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) -eq $false)
{
	$ArgumentList = "-noprofile -noexit -file `"{0}`" -Path `"$Path`" -MaxStage $MaxStage"
	If ($ValidateOnly) { $ArgumentList = $ArgumentList + " -ValidateOnly" }
	If ($SkipValidation) { $ArgumentList = $ArgumentList + " -SkipValidation $SkipValidation" }
	If ($Mode) { $ArgumentList = $ArgumentList + " -Mode $Mode" }
	Write-Host "elevating"
	Start-Process powershell.exe -Verb RunAs -ArgumentList ($ArgumentList -f ($myinvocation.MyCommand.Definition))
	Exit
}

$InstallerStage = [int]$MaxStage.SubString(0, 1)

$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$Host.UI.RawUI.WindowTitle = "PowerShell Deployment Toolkit"
$StartTime = Get-Date
$Validate = $true

# Check PS host
If ($Host.Name -ne 'ConsoleHost')
{
	$Validate = $false
	Write-Host "Installer.ps1 should not be run from ISE" -ForegroundColor Red
}

# Change to path
If (Test-Path $Path -PathType Container)
{
	Set-Location $Path
}
Else
{
	$Validate = $false
	Write-Host "Invalid path" -ForegroundColor Red
}
#endregion Startup

#region Setup
If ($Validate)
{
	If (!($ValidateOnly))
	{
		# Constants
		$LogFolder = "$env:LocalAppData\Installer"
		$LogFile = "Installer"
		
		# Variables
		$Deployment = [guid]::NewGuid().ToString()
		$Path = (Get-Location).Path
		$Global:LogCount = 0
		$UTCOffset = (New-TimeSpan -Start (Get-Date) -End (Get-Date).ToUniversalTime()).TotalMinutes
		If ($UTCOffset -ge 0) { $UTCOffset = "+" + $UTCOffset }
		
		# Create log folders, cleanup old data, initialize log file
		If (!(Test-Path -Path $LogFolder -PathType Container)) { New-Item -Path $LogFolder -ItemType Directory | Out-Null }
		If (!(Test-Path -Path "$LogFolder\Log" -PathType Container)) { New-Item -Path "$LogFolder\Log" -ItemType Directory | Out-Null }
		If (Test-Path -Path "$LogFolder\Log\*.log" -PathType Leaf) { Remove-Item -Path "$LogFolder\Log\*.log" }
		If (!(Test-Path -Path "$LogFolder\Temp" -PathType Container)) { New-Item -Path "$LogFolder\Temp" -ItemType Directory | Out-Null }
		If (Test-Path -Path "$LogFolder\Temp\*.sql" -PathType Leaf) { Remove-Item "$LogFolder\Temp\*.sql" }
		If (Test-Path -Path "$LogFolder\Temp\*.role" -PathType Leaf) { Remove-Item "$LogFolder\Temp\*.role" }
		If (Test-Path -Path "$LogFolder\Temp\*.status" -PathType Leaf) { Remove-Item -Path "$LogFolder\Temp\*.Status" }
		If (Test-Path -Path "$LogFolder\Temp\*.color" -PathType Leaf) { Remove-Item -Path "$LogFolder\Temp\*.color" }
		If (Test-Path -Path "$LogFolder\Temp\*.cert" -PathType Leaf) { Remove-Item -Path "$LogFolder\Temp\*.cert" }
		
		Function New-LogEntry ($Deployment, $LogFolder, $LogFile, $Server, $Message)
		{
			# Writes a single line to a temporary log file to be picked up by the central logger job
			$LogDate = Get-Date -Format MM-dd-yyyy
			$LogTime = Get-Date -Format HH:mm:ss.fff
			#$LogEntry = "$LogDate,$LogTime,$Deployment,$Server," + "{0:D4}" -f $Global:LogCount + ",$Message"
			$LogEntry = "{0:D4}" -f $Global:LogCount + "::$Message`$`$<$Server><$LogDate $LogTime$UTCOffset><$Deployment>"
			Add-Content -Path "$LogFolder\Log\$Server.$Global:LogCount.log" -Value $LogEntry
			$Global:LogCount++
		}
		
		New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server "Controller" -Message "Start"
		New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server "Controller" -Message "Reading input files"
	}
	
	# Read input files
	If (Test-Path "$Path\Workflow.xml")
	{
		try { $Workflow = [XML] (Get-Content "$Path\Workflow.xml") }
		catch { $Validate = $false; Write-Host "Invalid Workflow.xml" -ForegroundColor Red }
	}
	Else
	{
		$Validate = $false
		Write-Host "Missing Workflow.xml" -ForegroundColor Red
	}
	If (Test-Path "$Path\Extender*.xml")
	{
		Get-ChildItem -Path "$Path\Extender*.xml" | ForEach-Object {
			$ExtenderFile = $_.Name
			try { $Extender = [XML] (Get-Content "$Path\$ExtenderFile") }
			catch { $Validate = $false; Write-Host "Invalid Extender.xml" -ForegroundColor Red }
			If ($Validate)
			{
				$Extender.Installer.ServerFeatures | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderServerFeaturesOSVersion = $_.OSVersion
					$_.Group | Where-Object { $_ -ne $null } | ForEach-Object {
						$ExtenderServerFeaturesGroup = $_.Name
						$_.ServerFeature | Where-Object { $_ -ne $null } | ForEach-Object {
							$ExtenderServerFeature = $_
							If (!($Workflow.Installer.ServerFeatures | Where-Object { $_.OSVersion -eq $ExtenderServerFeaturesOSVersion } | ForEach-Object { $_.Group } | Where-Object { $_.Name -eq $ExtenderServerFeaturesGroup } | ForEach-Object { $_.ServerFeature } | Where-Object { $_.Name -eq $ExtenderServerFeature.Name }))
							{
								($Workflow.Installer.ServerFeatures | Where-Object { $_.OSVersion -eq $ExtenderServerFeaturesOSVersion } | ForEach-Object { $_.Group } | Where-Object { $_.Name -eq $ExtenderServerFeaturesGroup }).AppendChild($Workflow.ImportNode($ExtenderServerFeature, $true)) | Out-Null
							}
						}
					}
				}
				$Extender.Installer.Installables.Installable | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderInstallable = $_
					If (!($Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $ExtenderInstallable.Name }))
					{
						$Workflow.Installer.Installables.AppendChild($Workflow.ImportNode($ExtenderInstallable, $true)) | Out-Null
					}
				}
				$Extender.Installer.Components.Component | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderComponent = $_
					If (!($Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $ExtenderComponent.Name }))
					{
						$Workflow.Installer.Components.AppendChild($Workflow.ImportNode($ExtenderComponent, $true)) | Out-Null
					}
				}
				$Extender.Installer.SQL.SQL | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderSQL = $_
					If (!($Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $ExtenderSQL.Version }))
					{
						$Workflow.Installer.SQL.AppendChild($Workflow.ImportNode($ExtenderSQL, $true)) | Out-Null
					}
				}
				$Extender.Installer.Roles.Role | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderRole = $_
					If (!($Workflow.Installer.Role.Role | Where-Object { $_.Name -eq $ExtenderRole.Name }))
					{
						$Workflow.Installer.Roles.AppendChild($Workflow.ImportNode($ExtenderRole, $true)) | Out-Null
					}
				}
				$Extender.Installer.Integrations.Integration | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderIntegration = $_
					If (!($Workflow.Installer.Integrations.Integration | Where-Object { $_.Name -eq $ExtenderIntegration.Name }))
					{
						$Workflow.Installer.Integrations.AppendChild($Workflow.ImportNode($ExtenderIntegration, $true)) | Out-Null
					}
				}
			}
		}
	}
	If (Test-Path "$Path\Variable.xml")
	{
		try { $Variable = [XML] (Get-Content "$Path\Variable.xml") }
		catch { $Validate = $false; Write-Host "Invalid Variable.xml" -ForegroundColor Red }
	}
	Else
	{
		$Validate = $false
		Write-Host "Missing Variable.xml" -ForegroundColor Red
	}
}
#endregion Setup

#region Validation
If ($Validate)
{
	
	Function Set-ScriptVariable ($Name, $Value)
	{
		Invoke-Expression ("`$Script:" + $Name + " = `"" + $Value + "`"")
		If (($Name.Contains("ServiceAccount")) -and !($Name.Contains("Password")) -and ($Value -ne ""))
		{
			Invoke-Expression ("`$Script:" + $Name + "Domain = `"" + $Value.Split("\")[0] + "`"")
			Invoke-Expression ("`$Script:" + $Name + "Username = `"" + $Value.Split("\")[1] + "`"")
		}
	}
	
	$SystemDrive = $env:SystemDrive
	$Workflow.Installer | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
		Set-ScriptVariable -Name $_.Name -Value $_.Value
	}
	$Variable.Installer | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
		Set-ScriptVariable -Name $_.Name -Value $_.Value
	}
	
	$Servers = @($Variable.Installer.Roles.Role | Where-Object { ($_.Existing -ne "True") -and ($_.SQLCluster -ne "True") } | Sort-Object { $_.Server } -Unique | ForEach-Object { $_.Server })
	$SQLClusters = @($Variable.Installer.Roles.Role | Where-Object { ($_.Existing -ne "True") -and ($_.SQLCluster -eq "True") } | ForEach-Object { $_.Server })
	$SQLClusters | ForEach-Object {
		$SQLCluster = $_
		$SQLClusterNodes = $Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLCluster } | ForEach-Object { $_.Node.Server }
		$Servers += $SQLClusterNodes
	}
	$Servers = $Servers | Sort-Object -Unique
	
	$Roles = @($Variable.Installer.Roles.Role)
	
	If (!($SkipValidation | Where-Object { $_ -eq "All" }))
	{
		If (!($SkipValidation | Where-Object { $_ -eq "Local" }))
		{
			
			# Validate FQDN
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating FQDN..."
				Write-Host ""
				$Servers | ForEach-Object {
					Write-Host "    Server: $_... " -NoNewline
					If (@($_.Split(".")).Count -ge 3)
					{
						Write-Host "Passed" -ForegroundColor Green
					}
					Else
					{
						Write-Host "Failed" -ForegroundColor Red
						Write-Host "      FQDN required" -ForegroundColor Red
						$validate = $false
					}
				}
				Start-Sleep 1
			}
			
			# Validate dependencies
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating role dependencies..."
				Write-Host ""
				$Roles | ForEach-Object {
					$RoleValidate = $true
					$Role = $_.Name
					If ($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Dependency })
					{
						Write-Host "    Role: $Role... " -NoNewline
						$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Dependency } | ForEach-Object {
							$Dependency = $_.Name
							If (!($Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Dependency }))
							{
								$RoleValidate = $false
							}
						}
						If ($RoleValidate)
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							$Validate = $false
							$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Dependency } | ForEach-Object {
								$Dependency = $_.Name
								If (!($Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Dependency }))
								{
									Write-Host "      Missing dependency $Dependency" -ForegroundColor Red
								}
							}
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate role combinations
			If (!($SkipValidation | Where-Object { $_ -eq "RoleCombinations" }))
			{
				If ($Validate)
				{
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
						If ($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.Combinations })
						{
							Write-Host "    Role: $Role... " -NoNewline
							$Variable.Installer.Roles.Role | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object { $_.Name } | ForEach-Object {
								$Combination = $_
								If (($Role -ne $Combination) -and !(($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.Combinations.Combination } | Where-Object { $_ -eq $Combination })))
								{
									$RoleValidate = $false
								}
							}
							If ($RoleValidate)
							{
								Write-Host "Passed" -ForegroundColor Green
							}
							Else
							{
								Write-Host "Failed" -ForegroundColor Red
								$Validate = $false
								$Variable.Installer.Roles.Role | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object { $_.Name } | ForEach-Object {
									$Combination = $_
									If (($Role -ne $Combination) -and !(($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.Combinations.Combination } | Where-Object { $_ -eq $Combination })))
									{
										Write-Host "      Unsupported combination: $Combination" -ForegroundColor Red
									}
								}
							}
						}
					}
					Start-Sleep 1
				}
			}
			
			# Validate role instance count
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating role instance count..."
				Write-Host ""
				$Roles | ForEach-Object {
					$Role = $_.Name
					$Server = $_.Server
					If ($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.Multiple } | Where-Object { $_ -eq "False" })
					{
						Write-Host "    Role: $Role... " -NoNewline
						If (@($Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role }).Count -eq 1)
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						else
						{
							Write-Host "Failed" -ForegroundColor Red
							Write-Host "      $Role can have only one instance" -ForegroundColor Red
							$Validate = $false
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate required variables
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating required variables..."
				Write-Host ""
				Write-Host "    Global variables"
				$Workflow.Installer.Variable | Where-Object { $_.Required -eq "True" } | ForEach-Object {
					$RequiredVariable = $_.Name
					Write-Host "      Variable: $RequiredVariable... " -NoNewline
					If ((Get-Item "Variable:$RequiredVariable" -ErrorAction SilentlyContinue).Value)
					{
						Write-Host "Passed" -ForegroundColor Green
					}
					Else
					{
						Write-Host "Failed" -ForegroundColor Red
						$Validate = $false
					}
				}
				$Components = $Workflow.Installer.Components.Component | ForEach-Object { $_.Name }
				$Components | ForEach-Object {
					$Component = $_
					If ($Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable | Where-Object { $_.Required -eq "True" } })
					{
						$CR = $False
						$Workflow.Installer.Roles.Role | Where-Object { $_.Component -eq $Component } | ForEach-Object {
							$Role = $_.Name
							$Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object {
								If ($CR -eq $False)
								{
									Write-Host "    $Component Variables"
									$CR = $True
									$Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
										Set-ScriptVariable -Name $_.Name -Value $_.Value
									}
									$Variable.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
										Set-ScriptVariable -Name $_.Name -Value $_.Value
									}
									$Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable | Where-Object { $_.Required -eq "True" } } | ForEach-Object {
										$RequiredVariable = $_.Name
										Write-Host "      Variable: $RequiredVariable... " -NoNewline
										If ((Get-Item "Variable:$RequiredVariable" -ErrorAction SilentlyContinue).Value)
										{
											Write-Host "Passed" -ForegroundColor Green
										}
										Else
										{
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
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating SQL variables..."
				Write-Host ""
				$Workflow.Installer.Roles.Role | Where-Object { $_.SQL -eq "True" } | ForEach-Object {
					$RoleValidate = $True
					$Role = $_.Name
					$Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $Role) -and ($_.SQLCluster -ne "True") } | ForEach-Object {
						$Server = $_.Server
						Write-Host "    Role: $Role"
						Write-Host "      Instance... " -NoNewline
						If ($Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $Role) -and ($_.Instance -ne $null) })
						{
							$Instance = $_.Instance
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							Write-Host "        SQL Server instance not specified" -ForegroundColor Red
							$Validate = $False
							$RoleValidate = $False
						}
						If ($RoleValidate)
						{
							Write-Host "      SQL Server version for instance... " -NoNewline
							If ($Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) -and ($_.Version -ne $null) })
							{
								$SQLVersion = $Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object { $_.Version }
								If ($Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion })
								{
									Write-Host "Passed" -ForegroundColor Green
								}
								Else
								{
									Write-Host "Failed" -ForegroundColor Red
									Write-Host "        Invalid SQL Server version" -ForegroundColor Red
									$Validate = $False
									$RoleValidate = $False
								}
							}
							Else
							{
								Write-Host "Failed" -ForegroundColor Red
								Write-Host "        SQL Server version not specified" -ForegroundColor Red
								$Validate = $False
								$RoleValidate = $False
							}
						}
						If ($RoleValidate)
						{
							$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Required -eq "True" } | ForEach-Object {
								$RequiredVariable = $_.Name
								$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								$Variable.Installer.SQL.Server | Where-Object { ($_.Server -eq $Server) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								$Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								Write-Host "      Variable: $RequiredVariable... " -NoNewline
								If ((Get-Item "Variable:$RequiredVariable" -ErrorAction SilentlyContinue).Value)
								{
									Write-Host "Passed" -ForegroundColor Green
								}
								Else
								{
									Write-Host "Failed" -ForegroundColor Red
									$Validate = $false
								}
							}
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate SQL cluster variables
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating SQL cluster variables..."
				Write-Host ""
				$Workflow.Installer.Roles.Role | Where-Object { $_.SQL -eq "True" } | ForEach-Object {
					$RoleValidate = $True
					$Role = $_.Name
					$Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $Role) -and ($_.SQLCluster -eq "True") } | ForEach-Object {
						$Server = $_.Server
						Write-Host "    Role: $Role"
						Write-Host "      Instance... " -NoNewline
						If ($Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $Role) -and ($_.Instance -ne $null) })
						{
							$Instance = $_.Instance
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							Write-Host "        SQL Server instance not specified" -ForegroundColor Red
							$Validate = $False
							$RoleValidate = $False
						}
						If ($RoleValidate)
						{
							Write-Host "      SQL Server version for cluster... " -NoNewline
							If ($Variable.Installer.SQL.Cluster | Where-Object { ($_.Cluster -eq $Server) -and ($_.Version -ne $null) })
							{
								$SQLVersion = $Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $Server } | ForEach-Object { $_.Version }
								If ($Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion })
								{
									Write-Host "Passed" -ForegroundColor Green
								}
								Else
								{
									Write-Host "Failed" -ForegroundColor Red
									Write-Host "        Invalid SQL Server version" -ForegroundColor Red
									$Validate = $False
									$RoleValidate = $False
								}
							}
							Else
							{
								Write-Host "Failed" -ForegroundColor Red
								Write-Host "        SQL Server version not specified" -ForegroundColor Red
								$Validate = $False
								$RoleValidate = $False
							}
						}
						If ($RoleValidate)
						{
							$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Cluster -eq "True" } | ForEach-Object {
								$RequiredVariable = $_.Name
								$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								$Variable.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $Server } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								Write-Host "      Variable: $RequiredVariable... " -NoNewline
								If ((Get-Item "Variable:$RequiredVariable" -ErrorAction SilentlyContinue).Value)
								{
									Write-Host "Passed" -ForegroundColor Green
								}
								Else
								{
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
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating SQL instance..."
				Write-Host ""
				$Workflow.Installer.Roles.Role | Where-Object { $_.Validation.SQL.Instance } | ForEach-Object {
					$Role = $_.Name
					$Roles | Where-Object { $_.Name -eq $Role } | ForEach-Object {
						Write-Host "    Role: $Role... " -NoNewline
						$SQLInstance = $Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Instance }
						If ($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.SQL.Instance } | Where-Object { $_ -eq $SQLInstance })
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							Write-Host "      Invalid SQL instance $SQLInstance" -ForegroundColor Red
							$Validate = $false
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate SQL port
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating SQL port..."
				Write-Host ""
				$Workflow.Installer.Roles.Role | Where-Object { $_.Validation.SQL.Port -eq "True" } | ForEach-Object {
					$Role = $_.Name
					$Roles | Where-Object { $_.Name -eq $Role } | ForEach-Object {
						Write-Host "    Role: $Role... " -NoNewline
						$SQLServer = $Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Server }
						$SQLInstance = $Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Instance }
						$SQLCluster = $Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.SQLCluster }
						If ($SQLCluster -eq "True")
						{
							$SQLPort = $Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLServer } | ForEach-Object { $_.Port }
						}
						Else
						{
							$SQLPort = $Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $SQLServer) -and ($_.Instance -eq $SQLInstance) } | ForEach-Object { $_.Port }
						}
						If (($SQLInstance -eq "MSSQLSERVER") -or ($SQLPort -ne $null))
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							Write-Host "      Missing port for SQL server $SQLServer instance $SQLInstance" -ForegroundColor Red
							$Validate = $false
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate NLB configuration
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating NLB configuration..."
				Write-Host ""
				$Components = $Workflow.Installer.Components.Component | ForEach-Object { $_.Name }
				$Components | ForEach-Object {
					$Component = $_
					$CR = $False
					$Workflow.Installer.Roles.Role | Where-Object { $_.Component -eq $Component } | ForEach-Object {
						$Role = $_.Name
						$Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object {
							If ($CR -eq $False)
							{
								$Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								$Variable.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								$Workflow.Installer.Roles.Role | Where-Object { ($_.Component -eq $Component) -and ($_.Validation.NLB -eq "True") } | ForEach-Object {
									$Role = $_.Name
									$Roles | Where-Object { $_.Name -eq $Role } | ForEach-Object {
										If (!($CR)) { Write-Host "    $Component NLB configuration" }
										$CR = $true
										If ((Invoke-Expression ("`$" + $Role.Replace(" ", "") + "NLBConfig")) -eq "True")
										{
											Write-Host "      Role: $Role... " -NoNewline
											If (!(Invoke-Expression ("`$" + $Role.Replace(" ", "") + "NLBName")) -or !(Invoke-Expression ("`$" + $Role.Replace(" ", "") + "NLBIPv4")))
											{
												Write-Host "Failed" -ForegroundColor Red
												Write-Host "        Missing either NLBName or NLBIPv4 variables" -ForegroundColor Red
												$Validate = $false
											}
											Else
											{
												If (((Invoke-Expression ("`$" + $Role.Replace(" ", "") + "NLBName")).Split(".").Count -eq 1) -or ((Invoke-Expression ("`$" + $Role.Replace(" ", "") + "NLBIPv4")).Split(".").Count -eq 1))
												{
													Write-Host "Failed" -ForegroundColor Red
													Write-Host "        NLBName and NLBIPv4 must be FQDN and IPv4 address" -ForegroundColor Red
													$Validate = $false
												}
												Else
												{
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
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating NLB combinations..."
				Write-Host ""
				$Roles | Where-Object { $_ -ne $null } | ForEach-Object {
					$RoleValidate = $true
					$Role = $_.Name
					$Server = $_.Server
					$VR = $true
					If ((Invoke-Expression ("`$" + $Role.Replace(" ", "") + "NLBConfig")) -eq "True")
					{
						$IPv4 = Invoke-Expression ("`$" + $Role.Replace(" ", "") + "NLBIPv4")
						If ($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.NLB })
						{
							Write-Host "    Role: $Role... " -NoNewline
							$Variable.Installer.Roles.Role | Where-Object { $_.Server -eq $Server } | ForEach-Object { $_.Name } | ForEach-Object {
								If (Invoke-Expression ("`$" + $_.Replace(" ", "") + "NLBIPv4"))
								{
									If ((Invoke-Expression ("`$" + $_.Replace(" ", "") + "NLBIPv4")) -ne $IPv4)
									{
										If ($VR)
										{
											$VR = $false
											Write-Host "Failed" -ForegroundColor Red
											Write-Host "      IPv4 addresses must be the same on combined NLB servers" -ForegroundColor Red
											$Validate = $False
										}
									}
								}
							}
							$Variable.Installer.Roles.Role | Where-Object { $_.Server -ne $Server } | ForEach-Object { $_.Name } | ForEach-Object {
								If (Invoke-Expression ("`$" + $_.Replace(" ", "") + "NLBIPv4"))
								{
									If ((Invoke-Expression ("`$" + $_.Replace(" ", "") + "NLBIPv4")) -eq $IPv4)
									{
										If ($VR)
										{
											$VR = $false
											Write-Host "Failed" -ForegroundColor Red
											Write-Host "      IPv4 addresses must be different on different NLB servers" -ForegroundColor Red
											$Validate = $False
										}
									}
								}
							}
						}
						If ($VR) { Write-Host "Passed" -ForegroundColor Green }
					}
				}
				Start-Sleep 1
			}
			
		If (!($SkipValidation | Where-Object { $_ -eq "Media" }))
		{	
			# Validate media
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Local)..."
				Write-Host ""
				Write-Host "  Validating media..."
				Write-Host ""
				# Get SQL versions
				$Installables = @("Windows Server 2012 R2", "Windows Server 2012")
				$Servers | ForEach-Object {
					$Server = $_
					$Variable.Installer.Roles.Role | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -ne $null) } | ForEach-Object { $_.Instance } | Sort-Object -Unique | ForEach-Object {
						$Instance = $_
						$Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object {
							$Installables += $_.Version
						}
					}
				}
				
				# Get roles
				$MRoles = @()
				$Servers | ForEach-Object {
					$Server = $_
					
					# Get roles for this server
					$MRoles += @($Variable.Installer.Roles.Role | Where-Object { $_.Server -eq $Server } | Where-Object { $_.Existing -ne "True" } | ForEach-Object { $_.Name })
					
					# Get SQL cluster roles for this server
					$Variable.Installer.SQL.Cluster | ForEach-Object {
						$SQLCluster = $_.Cluster
						$_.Node | Where-Object { $_.Server -eq $Server } | ForEach-Object {
							$SQLClusterNode = $_.Server
							$SQLClusterNodes = $Variable.Installer.Roles.Role | Where-Object { $_.Server -eq $SQLCluster } | ForEach-Object { $_.Name }
							$MRoles += $SQLClusterNodes
						}
					}
					
					# Get integrations for this server
					# For each role on this server...
					$MRoles | ForEach-Object {
						$Role = $_
						$Integration = $false
						# ...find integrations targeted at that role
						$Workflow.Installer.Integrations.Integration | Where-Object { $_.Target -eq $Role } | ForEach-Object {
							$ThisIntegration = $_.Name
							$Integration = $true
							# Check that all integration dependencies exist in this deployment
							$_.Dependency | ForEach-Object {
								$Dependency = $_
								If (!($Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Dependency }))
								{
									$Integration = $false
								}
							}
							If ($Integration)
							{
								$MRoles += $ThisIntegration
							}
						}
					}
				}
				$MRoles = $MRoles | Sort-Object -Unique
				
				# Get installables
				$MRoles | ForEach-Object {
					$Role = $_
					$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object {
						$_.Prerequisites | ForEach-Object {
							$_.Prerequisite | ForEach-Object {
								$Prerequisite = $_.Name
								$Workflow.Installer.Installables.Installable | ForEach-Object {
									$InstallableName = $_.Name
									If ($_.Install | Where-Object { $_.Name -eq $Prerequisite })
									{
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
					$Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $Installable } | ForEach-Object {
						If ($_.AdditionalDownload)
						{
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
					$Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $Installable } | ForEach-Object {
						If ($_.Variable)
						{
							$_.Variable | ForEach-Object {
								If (Get-Variable $_.Name -ErrorAction SilentlyContinue)
								{
									Set-Variable -Name $_.Name -Value $_.Value
								}
								Else
								{
									New-Variable -Name $_.Name -Value $_.Value
								}
							}
						}
					}
					$Variable.Installer.Installables.Installable | Where-Object { $_.Name -eq $Installable } | ForEach-Object {
						If ($_.Variable)
						{
							$_.Variable | ForEach-Object {
								If (Get-Variable $_.Name -ErrorAction SilentlyContinue)
								{
									Set-Variable -Name $_.Name -Value $_.Value
								}
								Else
								{
									New-Variable -Name $_.Name -Value $_.Value
								}
							}
						}
					}
					$Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $Installable } | ForEach-Object {
						$DownloadName = $_.Name
						If ($_.Download)
						{
							$DownloadFolder = Invoke-Expression ($_.SourceFolder)
							@($_.Download)[0] | ForEach-Object {
								$DownloadItem = $_
								$DownloadType = $_.Type
								Write-Host "    $DownloadName... " -NoNewline
								Switch ($DownloadType)
								{
									"Download" {
										$DownloadFile = $DownloadItem.File
										If (Test-Path "$SourcePath\$DownloadFolder\$DownloadFile")
										{
											$DownloadFileType = $DownloadFile.Split(".")[$DownloadFile.Split(".").Count - 1]
											Switch ($DownloadFileType)
											{
												"exe" {
													$Result = $false
													$DownloadFileVersion = $DownloadItem.FileVersion.Split("/")
													$DownloadFileVersion | ForEach-Object { If ((Get-Item "$SourcePath\$DownloadFolder\$DownloadFile").VersionInfo.ProductVersion -eq $_) { $Result = $true } }
													
													If ($Result)
													{
														Write-Host "Passed" -ForegroundColor Green
													}
													Else
													{
														Write-Host "Failed" -ForegroundColor Red
														Write-Host "      $SourcePath\$DownloadFolder\$DownloadFile incorrect version" -ForegroundColor Red
														$Validate = $false
													}
													Break
												}
												Default
												{
													$Result = $false
													$DownloadFileSize = $DownloadItem.FileSize.Split("/")
													$DownloadFileSize | ForEach-Object { If ((Get-Item "$SourcePath\$DownloadFolder\$DownloadFile").Length -eq $_) { $Result = $true } }
													
													If ($Result)
													{
														Write-Host "Passed" -ForegroundColor Green
													}
													Else
													{
														Write-Host "Failed" -ForegroundColor Red
														Write-Host "      $SourcePath\$DownloadFolder\$DownloadFile incorrect size" -ForegroundColor Red
														$Validate = $false
													}
												}
											}
										}
										Else
										{
											Write-Host "Failed" -ForegroundColor Red
											Write-Host "      $SourcePath\$DownloadFolder\$DownloadFile missing" -ForegroundColor Red
											$Validate = $false
										}
									}
									"DownloadRun" {
										$ExistingFile = @($DownloadItem.Run.ExistingFile)[0]
										If (Test-Path "$SourcePath\$DownloadFolder\$ExistingFile")
										{
											$ExistingFileType = $ExistingFile.Split(".")[$ExistingFile.Split(".").Count - 1]
											Switch ($ExistingFileType)
											{
												"exe" {
													$Result = $false
													$ExistingFileVersion = @($DownloadItem.Run)[0].FileVersion.Split("/")
													$ExistingFileVersion | ForEach-Object { If ((Get-Item "$SourcePath\$DownloadFolder\$ExistingFile").VersionInfo.ProductVersion -eq $_) { $Result = $true } }
													
													If ($Result)
													{
														Write-Host "Passed" -ForegroundColor Green
													}
													Else
													{
														Write-Host "Failed" -ForegroundColor Red
														Write-Host "      $SourcePath\$DownloadFolder\$ExistingFile incorrect version" -ForegroundColor Red
														$Validate = $false
													}
													Break
												}
												Default
												{
													$Result = $false
													$ExistingFileSize = @($DownloadItem.Run)[0].FileSize.Split("/")
													$ExistingFileSize | ForEach-Object { If ((Get-Item "$SourcePath\$DownloadFolder\$ExistingFile").Length -eq $_) { $Result = $true } }
													
													If ($Result)
													{
														Write-Host "Passed" -ForegroundColor Green
													}
													Else
													{
														Write-Host "Failed" -ForegroundColor Red
														Write-Host "      $SourcePath\$DownloadFolder\$ExistingFile incorrect size" -ForegroundColor Red
														$Validate = $false
													}
												}
											}
										}
										Else
										{
											Write-Host "Failed" -ForegroundColor Red
											Write-Host "      $SourcePath\$DownloadFolder\$ExistingFile missing" -ForegroundColor Red
											$Validate = $false
										}
									}
									"DownloadExtract" {
										$ExistingFile = $DownloadItem.Extract.ExistingFile
										If (Test-Path "$SourcePath\$DownloadFolder\$ExistingFile")
										{
											$ExistingFileType = $ExistingFile.Split(".")[$ExistingFile.Split(".").Count - 1]
											Switch ($ExistingFileType)
											{
												"exe" {
													$Result = $false
													$ExistingFileVersion = @($DownloadItem.Extract)[0].FileVersion.Split("/")
													$ExistingFileVersion | ForEach-Object { If ((Get-Item "$SourcePath\$DownloadFolder\$ExistingFile").VersionInfo.ProductVersion -eq $_) { $Result = $true } }
													
													If ($Result)
													{
														Write-Host "Passed" -ForegroundColor Green
													}
													Else
													{
														Write-Host "Failed" -ForegroundColor Red
														Write-Host "      $SourcePath\$DownloadFolder\$ExistingFile incorrect version" -ForegroundColor Red
														$Validate = $false
													}
													Break
												}
												Default
												{
													$Result = $false
													$ExistingFileSize = @($DownloadItem.Extract)[0].FileSize.Split("/")
													$ExistingFileSize | ForEach-Object { If ((Get-Item "$SourcePath\$DownloadFolder\$ExistingFile").Length -eq $_) { $Result = $true } }
													
													If ($Result)
													{
														Write-Host "Passed" -ForegroundColor Green
													}
													Else
													{
														Write-Host "Failed" -ForegroundColor Red
														Write-Host "      $SourcePath\$DownloadFolder\$ExistingFile incorrect size" -ForegroundColor Red
														$Validate = $false
													}
												}
											}
										}
										Else
										{
											Write-Host "Failed" -ForegroundColor Red
											Write-Host "      $SourcePath\$DownloadFolder\$ExistingFile missing" -ForegroundColor Red
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
			
		}
		
		}
		If (!($SkipValidation | Where-Object { $_ -eq "ActiveDirectory" }))
		{
			
			# Validate service accounts
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (ActiveDirectory)..."
				Write-Host ""
				Write-Host "  Validating service accounts..."
				Write-Host ""
				Write-Host "    Global service accounts"
				Add-Type -AssemblyName System.DirectoryServices.AccountManagement
				$Workflow.Installer.Variable | Where-Object { ($_.Name.Contains("ServiceAccount")) -and !($_.Name.Contains("Password")) } | ForEach-Object {
					$ServiceAccountName = $_.Name
					Write-Host "      Service account: $ServiceAccountName... " -NoNewline
					$ServiceAccount = (Get-Item "Variable:$ServiceAccountName").Value
					If ($ServiceAccount.Split("\").Count -eq 2)
					{
						$Domain = $ServiceAccount.Split("\")[0]
						$Username = $ServiceAccount.Split("\")[1]
						$Password = (Get-Item "Variable:$ServiceAccountName`Password").Value
						If ($Password -ne "")
						{
							$ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
							$PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType, $Domain)
							If ($PrincipalContext.ValidateCredentials($Username, $Password))
							{
								Write-Host "Passed" -ForegroundColor Green
							}
							Else
							{
								Write-Host "Failed" -ForegroundColor Red
								Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
								$Validate = $false
							}
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
							$Validate = $false
						}
					}
					Else
					{
						Write-Host "Failed" -ForegroundColor Red
						Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
						$Validate = $false
					}
				}
				$Components = $Workflow.Installer.Components.Component | ForEach-Object { $_.Name }
				$Components | ForEach-Object {
					$Component = $_
					If ($Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { ($_ -ne $null) -and ($_.Name.Contains("ServiceAccount")) })
					{
						$CR = $false
						$Workflow.Installer.Roles.Role | Where-Object { $_.Component -eq $Component } | ForEach-Object {
							$Role = $_.Name
							If ($Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role })
							{
								If ($CR -eq $false)
								{
									Write-Host "    $Component service accounts"
									$CR = $true
									$Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name.Contains("ServiceAccount") } | ForEach-Object {
										Set-ScriptVariable -Name $_.Name -Value $_.Value
									}
									$Variable.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name.Contains("ServiceAccount") } | ForEach-Object {
										Set-ScriptVariable -Name $_.Name -Value $_.Value
									}
									$Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name.Contains("ServiceAccount") } | ForEach-Object {
										If (!($_.Name.Contains("Password")))
										{
											$ServiceAccountName = $_.Name
											Write-Host "      Service account: $ServiceAccountName... " -NoNewline
											$ServiceAccount = (Get-Item "Variable:$ServiceAccountName").Value
											If ($ServiceAccount.Split("\").Count -eq 2)
											{
												$Domain = $ServiceAccount.Split("\")[0]
												$Username = $ServiceAccount.Split("\")[1]
												$Password = (Get-Item "Variable:$ServiceAccountName`Password").Value
												If ($Password -ne "")
												{
													$ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
													$PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType, $Domain)
													If ($PrincipalContext.ValidateCredentials($Username, $Password))
													{
														Write-Host "Passed" -ForegroundColor Green
													}
													Else
													{
														Write-Host "Failed" -ForegroundColor Red
														Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
														$Validate = $false
													}
												}
												Else
												{
													Write-Host "Failed" -ForegroundColor Red
													Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
													$Validate = $false
												}
											}
											Else
											{
												Write-Host "Failed" -ForegroundColor Red
												Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
												$Validate = $false
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
			
			# Validate SQL service accounts
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (ActiveDirectory)..."
				Write-Host ""
				Write-Host "  Validating SQL service accounts..."
				Write-Host ""
				$Variable.Installer.SQL.Instance | ForEach-Object {
					$Server = $_.Server
					$Instance = $_.Instance
					$SQLVersion = $_.Version
					Write-Host "    $Server $Instance"
					$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object {
						$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						$Variable.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						$Variable.Installer.SQL.Server | Where-Object { $_.Server -eq $Server } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						$Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { ($_.Name.Contains("ServiceAccount")) -and !($_.Name.Contains("Password")) } | ForEach-Object {
							$ServiceAccountName = $_.Name
							If ((Get-Item "Variable:$ServiceAccountName" -ErrorAction SilentlyContinue).Value)
							{
								$ServiceAccount = (Get-Item "Variable:$ServiceAccountName").Value
								Write-Host "      Service account: $ServiceAccountName ... " -NoNewline
								If ($ServiceAccount.Split("\").Count -eq 2)
								{
									$Domain = $ServiceAccount.Split("\")[0]
									$Username = $ServiceAccount.Split("\")[1]
									$Password = (Get-Item "Variable:$ServiceAccountName`Password").Value
									If ($Password -ne "")
									{
										$ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
										$PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType, $Domain)
										If ($PrincipalContext.ValidateCredentials($Username, $Password))
										{
											Write-Host "Passed" -ForegroundColor Green
										}
										Else
										{
											Write-Host "Failed" -ForegroundColor Red
											Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
											$Validate = $false
										}
									}
									Else
									{
										Write-Host "Failed" -ForegroundColor Red
										Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
										$Validate = $false
									}
								}
								Else
								{
									Write-Host "Failed" -ForegroundColor Red
									Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
									$Validate = $false
								}
							}
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate SQL cluster service accounts
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (ActiveDirectory)..."
				Write-Host ""
				Write-Host "  Validating SQL cluster service accounts..."
				Write-Host ""
				$Variable.Installer.SQL.Cluster | ForEach-Object {
					$Server = $_.Cluster
					$SQLVersion = $_.Version
					Write-Host "    $Server"
					$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object {
						$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						$Variable.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $Server } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { ($_.Name.Contains("ServiceAccount")) -and !($_.Name.Contains("Password")) } | ForEach-Object {
							$ServiceAccountName = $_.Name
							If ((Get-Item "Variable:$ServiceAccountName" -ErrorAction SilentlyContinue).Value)
							{
								$ServiceAccount = (Get-Item "Variable:$ServiceAccountName").Value
								Write-Host "      Service account: $ServiceAccountName ... " -NoNewline
								If ($ServiceAccount.Split("\").Count -eq 2)
								{
									$Domain = $ServiceAccount.Split("\")[0]
									$Username = $ServiceAccount.Split("\")[1]
									$Password = (Get-Item "Variable:$ServiceAccountName`Password").Value
									If ($Password -ne "")
									{
										$ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
										$PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType, $Domain)
										If ($PrincipalContext.ValidateCredentials($Username, $Password))
										{
											Write-Host "Passed" -ForegroundColor Green
										}
										Else
										{
											Write-Host "Failed" -ForegroundColor Red
											Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
											$Validate = $false
										}
									}
									Else
									{
										Write-Host "Failed" -ForegroundColor Red
										Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
										$Validate = $false
									}
								}
								Else
								{
									Write-Host "Failed" -ForegroundColor Red
									Write-Host "        Invalid service account $ServiceAccount" -ForegroundColor Red
									$Validate = $false
								}
							}
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate role security principals
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (ActiveDirectory)..."
				Write-Host ""
				Write-Host "  Validating role security principals..."
				Write-Host ""
				$Components = $Workflow.Installer.Components.Component | ForEach-Object { $_.Name }
				$Components | ForEach-Object {
					$Component = $_
					If ($Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable | Where-Object { $_.Principal -eq "True" } })
					{
						$CR = $False
						$ADSearch = New-Object System.DirectoryServices.DirectorySearcher
						$Workflow.Installer.Roles.Role | Where-Object { $_.Component -eq $Component } | ForEach-Object {
							$Role = $_.Name
							$Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object {
								If ($CR -eq $False)
								{
									Write-Host "    $Component security principals"
									$CR = $True
									$Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
										Set-ScriptVariable -Name $_.Name -Value $_.Value
									}
									$Variable.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
										Set-ScriptVariable -Name $_.Name -Value $_.Value
									}
									$Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable | Where-Object { $_.Principal -eq "True" } } | ForEach-Object {
										$Principal = $_.Name
										If ((Get-Item "Variable:$Principal").Value)
										{
											Write-Host "      Principal: $Principal... " -NoNewline
											$PrincipalValidate = $false
											$PrincipalValue = (Get-Item "Variable:$Principal").Value
											$PrincipalValueUserGroup = $PrincipalValue.Split("\")[1]
											$ADSearch.Filter = ("(&(objectCategory=user)(CN=$PrincipalValueUserGroup))")
											If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
											$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483644)(CN=$PrincipalValueUserGroup))")
											If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
											$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483646)(CN=$PrincipalValueUserGroup))")
											If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
											$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483640)(CN=$PrincipalValueUserGroup))")
											If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
											If ($PrincipalValidate)
											{
												Write-Host "Passed" -ForegroundColor Green
											}
											Else
											{
												Write-Host "Failed" -ForegroundColor Red
												Write-Host "        $PrincipalValue is not a valid security principal" -ForegroundColor Red
												$Validate = $false
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
			
			# Validate SQL security principals
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (ActiveDirectory)..."
				Write-Host ""
				Write-Host "  Validating SQL security principals..."
				Write-Host ""
				$Variable.Installer.SQL.Instance | ForEach-Object {
					$Server = $_.Server
					$Instance = $_.Instance
					$SQLVersion = $_.Version
					$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Principal -eq "True" } | ForEach-Object {
						$Principal = $_.Name
						$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						$Variable.Installer.SQL.Server | Where-Object { ($_.Server -eq $Server) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						$Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						Write-Host "      $Server $Instance principal: $Principal... " -NoNewline
						$PrincipalValidate = $false
						$PrincipalValue = (Get-Item "Variable:$Principal").Value
						$PrincipalValueUserGroup = $PrincipalValue.Split("\")[1]
						$ADSearch.Filter = ("(&(objectCategory=user)(CN=$PrincipalValueUserGroup))")
						If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
						$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483644)(CN=$PrincipalValueUserGroup))")
						If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
						$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483646)(CN=$PrincipalValueUserGroup))")
						If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
						$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483640)(CN=$PrincipalValueUserGroup))")
						If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
						If ($PrincipalValidate)
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							Write-Host "        $PrincipalValue is not a valid security principal" -ForegroundColor Red
							$Validate = $false
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate SQL cluster security principals
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (ActiveDirectory)..."
				Write-Host ""
				Write-Host "  Validating SQL cluster security principals..."
				Write-Host ""
				$Variable.Installer.SQL.Cluster | ForEach-Object {
					$Server = $_.Cluster
					$SQLVersion = $_.Version
					$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Principal -eq "True" } | ForEach-Object {
						$Principal = $_.Name
						$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $Server } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						Write-Host "      $Server principal: $Principal... " -NoNewline
						$PrincipalValidate = $false
						$PrincipalValue = (Get-Item "Variable:$Principal").Value
						$PrincipalValueUserGroup = $PrincipalValue.Split("\")[1]
						$ADSearch.Filter = ("(&(objectCategory=user)(CN=$PrincipalValueUserGroup))")
						If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
						$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483644)(CN=$PrincipalValueUserGroup))")
						If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
						$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483646)(CN=$PrincipalValueUserGroup))")
						If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
						$ADSearch.Filter = ("(&(objectCategory=group)(grouptype=-2147483640)(CN=$PrincipalValueUserGroup))")
						If ($ADSearch.FindOne()) { $PrincipalValidate = $true }
						If ($PrincipalValidate)
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							Write-Host "        $PrincipalValue is not a valid security principal" -ForegroundColor Red
							$Validate = $false
						}
					}
				}
				Start-Sleep 1
			}
			
		}
		If (!($SkipValidation | Where-Object { $_ -eq "Remote" }))
		{
			
			# Create creds
			If ($Validate)
			{
				$SecurePassword = ConvertTo-SecureString $InstallerServiceAccountPassword -AsPlainText -Force
				$Credentials = New-Object System.Management.Automation.PSCredential ($InstallerServiceAccount, $SecurePassword)
			}
			
			# Validate servers and access
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating servers and access..."
				Write-Host ""
				$Servers | ForEach-Object {
					$Server = $_
					$ServerShort = $_.Split(".")[0]
					Write-Host "    Server: $Server"
					# Validate current user
					Write-Host "      Current user access... " -NoNewline
					$OS = $null
					try
					{
						$OS = Get-WMIObject -Class Win32_OperatingSystem -Namespace root/cimv2 -ComputerName $Server -ErrorAction SilentlyContinue
					}
					catch
					{
						$validate = $false
					}
					If ($OS -ne $null)
					{
						Write-Host "Passed" -ForegroundColor Green
					}
					Else
					{
						Write-Host "Failed" -ForegroundColor Red
						$validate = $false
					}
					# Validate installer user
					Write-Host "      $InstallerServiceAccount access... " -NoNewline
					If ($ServerShort -eq $env:ComputerName)
					{
						$ValidateLocal = $false
						$AdminGroup = (Get-WMIObject Win32_Group -filter "LocalAccount=True AND SID='S-1-5-32-544'" -ComputerName $Server).Name
						$Group = [ADSI]("WinNT://$Server/$AdminGroup,group")
						$Group.Members() | ForEach-Object {
							$AdsPath = $_.GetType().InvokeMember("Adspath", 'GetProperty', $Null, $_, $Null)
							$A = $AdsPath.split('/', [StringSplitOptions]::RemoveEmptyEntries)
							$Name = $A[2]
							$Domain = $A[1]
							$Class = $_.GetType().InvokeMember("Class", 'GetProperty', $Null, $_, $Null)
							If (($Class -eq "User") -and ($Domain -eq $InstallerServiceAccount.Split("\")[0]) -and ($Name -eq $InstallerServiceAccount.Split("\")[1])) { $ValidateLocal = $true }
						}
						If ($ValidateLocal)
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							$validate = $false
						}
					}
					Else
					{
						$OS = $null
						try
						{
							$OS = Get-WMIObject -Class Win32_OperatingSystem -Namespace root/cimv2 -ComputerName $Server -Credential $Credentials -ErrorAction SilentlyContinue
						}
						catch
						{
							$validate = $false
						}
						If ($OS -ne $null)
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							$validate = $false
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate incompatible software
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating Incompatible Software..."
				Write-Host ""
				$Servers | ForEach-Object {
					Write-Host "    Server: $_... "
					$Server = $_
					$Roles | Where-Object { $_.Server -eq $Server } | ForEach-Object {
						$IS = @()
						$Role = $_.Name
						Write-Host "      Role: $Role... " -NoNewline
						$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.Compatibility.IncompatibleSoftware } | ForEach-Object {
							$Name = $_.Name
							$Type = $_.Type
							$Value = $_.Value
							Switch ($Type)
							{
								"ProductCode" {
									@($Value.Split("/")) | ForEach-Object {
										$SearchCode = $_
										If (Get-WMIObject -Class Win32_Product -Namespace root/cimv2 -ComputerName $Server | Where-Object { $_.IdentifyingNumber -eq $SearchCode }) { $IS += $Name }
									}
								}
								"ProductCodeVersion" {
									@($Value.Split("/")) | ForEach-Object {
										$SearchCode = $_.Split("}")[0] + "}"
										$SearchVersion = $_.Split("}")[1]
										If (Get-WMIObject -Class Win32_Product -Namespace root/cimv2 -ComputerName $Server | Where-Object { ($_.IdentifyingNumber -eq $SearchCode) -and ($_.Version -eq $SearchVersion) }) { $IS += $Name }
									}
								}
							}
						}
						If ($IS.Count -eq 0)
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							$IS | ForEach-Object {
								Write-Host "        Incompatible software: $_" -ForegroundColor Red
							}
							$validate = $false
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate role clusters
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating role clusters..."
				Write-Host ""
				$Roles | ForEach-Object {
					$Role = $_.Name
					$Server = $_.Server
					If ($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.Cluster })
					{
						Write-Host "    Role: $Role... " -NoNewline
						$ClusterName = (Get-WmiObject -Class MSCluster_Cluster -Namespace root/mscluster -ComputerName $Server -Authentication PacketPrivacy -ErrorAction SilentlyContinue).Name
						If ($ClusterName -ne $null)
						{
							$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object {
								$NodeRole = $_.Validation.Cluster
								$NodeServer = $Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $NodeRole } | ForEach-Object { $_.Server }
								If ($NodeServer -ne $null)
								{
									If ($ClusterName -eq (Get-WmiObject -Class MSCluster_Cluster -Namespace root/mscluster -ComputerName $NodeServer -Authentication PacketPrivacy -ErrorAction SilentlyContinue).Name)
									{
										Write-Host "Passed" -ForegroundColor Green
									}
									Else
									{
										Write-Host "Failed" -ForegroundColor Red
										Write-Host "      $NodeServer is not a member of cluster $ClusterName" -ForegroundColor Red
										$validate = $false
									}
								}
								Else
								{
									Write-Host "Failed" -ForegroundColor Red
									Write-Host "      $NodeRole missing" -ForegroundColor Red
									$validate = $false
								}
							}
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							Write-Host "      $Server is not a cluster node" -ForegroundColor Red
							$validate = $false
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate SQL clusters
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating SQL clusters..."
				Write-Host ""
				$Variable.Installer.Roles.Role | Where-Object { $_.SQLCluster -eq "True" } | ForEach-Object {
					$RoleValidate = $true
					$Role = $_.Name
					Write-Host "    Role: $Role... " -NoNewline
					$Server = $_.Server
					$ClusterName = $null
					$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $Server } | ForEach-Object {
						$_.Node | ForEach-Object {
							$NodeServer = $_.Server
							If ($ClusterName -eq $null) { $ClusterName = (Get-WmiObject -Class MSCluster_Cluster -Namespace root/mscluster -ComputerName $NodeServer -Authentication PacketPrivacy -ErrorAction SilentlyContinue).Name }
							If ($ClusterName -ne $null)
							{
								If (!($ClusterName -eq (Get-WmiObject -Class MSCluster_Cluster -Namespace root/mscluster -ComputerName $NodeServer -Authentication PacketPrivacy -ErrorAction SilentlyContinue).Name))
								{
									If ($RoleValidate) { Write-Host "Failed" -ForegroundColor Red }
									Write-Host "      $NodeServer is not a member of cluster $ClusterName" -ForegroundColor Red
									$Validate = $false
									$RoleValidate = $false
								}
							}
							Else
							{
								Write-Host "Failed" -ForegroundColor Red
								Write-Host "      $NodeServer is not a cluster node" -ForegroundColor Red
								$Validate = $false
								$RoleValidate = $false
							}
						}
						If ($RoleValidate) { Write-Host "Passed" -ForegroundColor Green }
					}
				}
				Start-Sleep 1
			}
			
			# Validate WinRM
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating WinRM..."
				Write-Host ""
				$Servers | ForEach-Object {
					Write-Host "    Server: $_... " -NoNewline
					$WinRM = $null
					try
					{
						$WinRM = Invoke-Command -ComputerName $_ -ScriptBlock { Get-Service | Where-Object { ($_.Name -eq "WinRM") -and ($_.Status -eq "Running") } } -ErrorAction SilentlyContinue
					}
					catch
					{
						$validate = $false
					}
					If ($WinRM -ne $null)
					{
						Write-Host "Passed" -ForegroundColor Green
					}
					Else
					{
						Write-Host "Failed" -ForegroundColor Red
						$validate = $false
					}
				}
				Start-Sleep 1
			}
			
			# Validate Task Scheduler
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating Task Scheduler..."
				Write-Host ""
				$Servers | ForEach-Object {
					Write-Host "    Server: $_... " -NoNewline
					If (Get-Service -ComputerName $_ | Where-Object { ($_.Name -eq "Schedule") -and ($_.Status -eq "Running") })
					{
						Write-Host "Passed" -ForegroundColor Green
					}
					Else
					{
						Write-Host "Failed" -ForegroundColor Red
						$validate = $false
					}
				}
				Start-Sleep 1
			}
			
			# Validate Credentials Policy
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating Credentials Policy..."
				Write-Host ""
				$Servers | ForEach-Object {
					Write-Host "    Server: $_... " -NoNewline
					try { $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $_) }
					catch { $reg = $null }
					If ($reg -ne $Null)
					{
						$regKey = $reg.OpenSubKey("System\\CurrentControlSet\\Control\\Lsa")
						If ($regKey -ne $Null)
						{
							If ($regkey.GetValue('DisableDomainCreds') -eq 1)
							{
								Write-Host "Failed" -ForegroundColor Red
								$validate = $false
							}
							Else
							{
								Write-Host "Passed" -ForegroundColor Green
							}
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate operating system for role
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating operating system for roles..."
				Write-Host ""
				$Roles | Where-Object { $_.Existing -ne "True" } | ForEach-Object {
					$RoleValidate = $true
					$Role = $_.Name
					$Server = $_.Server
					If ($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.OperatingSystems })
					{
						Write-Host "    Role: $Role... " -NoNewline
						If ($Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $Role) -and ($_.SQLCluster -ne $null) })
						{
							$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $Server } | ForEach-Object { $_.Node } | ForEach-Object {
								$OSVersion = (Get-WMIObject -Class Win32_OperatingSystem -Namespace root/cimv2 -ComputerName $_.Server -ErrorAction SilentlyContinue).Version
								If (!($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.OperatingSystems.OperatingSystem.Version } | Where-Object { $_ -eq $OSVersion }) -and !($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.OperatingSystems.OperatingSystem } | Where-Object { $_ -eq $OSVersion }))
								{
									If ($RoleValidate) { Write-Host "Failed" -ForegroundColor Red }
									Write-Host "      Operating system version $OSVersion not supported for this role" -ForegroundColor Red
									$Validate = $false
									$RoleValidate = $false
								}
							}
						}
						Else
						{
							$OSVersion = (Get-WMIObject -Class Win32_OperatingSystem -Namespace root/cimv2 -ComputerName $Server -ErrorAction SilentlyContinue).Version
							If (!($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.OperatingSystems.OperatingSystem.Version } | Where-Object { $_ -eq $OSVersion }) -and !($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.OperatingSystems.OperatingSystem } | Where-Object { $_ -eq $OSVersion }))
							{
								Write-Host "Failed" -ForegroundColor Red
								Write-Host "      Operating system version $OSVersion not supported for this role" -ForegroundColor Red
								$Validate = $false
								$RoleValidate = $false
							}
							Else
							{
								$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.OperatingSystems.OperatingSystem } | Where-Object { $_.Version -eq $OSVersion } | ForEach-Object { $_.Feature } | Where-Object { $_ -ne $null } | ForEach-Object {
									$ServerFeatureName = $_.Name
									$ServerFeatureValidation = $_.Validation
									If (!(Get-WmiObject -Class Win32_ServerFeature -ComputerName $Server | Where-Object { $_.ID -eq $ServerFeatureValidation }))
									{
										Write-Host "Failed" -ForegroundColor Red
										Write-Host "      Missing operating system feature $ServerFeatureName" -ForegroundColor Red
										$Validate = $false
										$RoleValidate = $false
									}
								}
							}
						}
						If ($RoleValidate)
						{
							Write-Host "Passed" -ForegroundColor Green
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate file access
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating file access..."
				Write-Host ""
				$Servers | ForEach-Object {
					$Server = $_
					Write-Host "    Server: $_... " -NoNewline
					$OS = Get-WMIObject -Class Win32_OperatingSystem -Namespace root/cimv2 -ComputerName $Server -ErrorAction SilentlyContinue
					$SystemDrive = $OS.SystemDrive
					$Workflow.Installer.Variable | Where-Object { $_.Name -eq "TempPath" } | ForEach-Object { Invoke-Expression ("`$TempPath= `"" + $_.Value + "`"") }
					$Variable.Installer.Variable | Where-Object { $_.Name -eq "TempPath" } | ForEach-Object { Invoke-Expression ("`$TempPath= `"" + $_.Value + "`"") }
					$TestPath = "\\" + $Server + "\" + ($TempPath.Replace(":", "$")).Substring(0, 2)
					If (Get-Item $TestPath -ErrorAction SilentlyContinue)
					{
						Write-Host "Passed" -ForegroundColor Green
					}
					Else
					{
						Write-Host "Failed" -ForegroundColor Red
						Write-Host "      Cannot access $TestPath" -ForegroundColor Red
						$validate = $false
					}
				}
				Start-Sleep 1
			}
			
			# Validate certificates for role
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating certificates for roles..."
				Write-Host ""
				$Roles | Where-Object { $_.Existing -ne "True" } | ForEach-Object {
					$Role = $_.Name
					$Server = $_.Server
					If ($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.Certificate })
					{
						Write-Host "    Role: $Role... " -NoNewline
						$CertQuery = @(Invoke-Command -ComputerName $Server -ScriptBlock { $Server = $args[0]; If (!(Get-Module PKI)) { Import-Module PKI -ErrorAction SilentlyContinue }; If (Get-Module PKI) { Return (Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { ($_.Subject -eq "CN=$Server") -and ($_.Issuer -ne "CN=$Server") } | Where-Object { $_.EnhancedKeyUsageList.ObjectId -eq "1.3.6.1.5.5.7.3.1" }) } } -ArgumentList @($Server))
						If (($CertQuery.Count -eq 1) -and ($CertQuery[0] -ne $null))
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							$CertQuery = @(Invoke-Command -ComputerName $Server -ScriptBlock { $Server = $args[0]; If (!(Get-Module PKI)) { Import-Module PKI -ErrorAction SilentlyContinue }; If (Get-Module PKI) { Return (Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { ($_.Subject -eq "CN=$Server") -and ($_.Issuer -eq "CN=$Server") } | Where-Object { $_.EnhancedKeyUsageList.ObjectId -eq "1.3.6.1.5.5.7.3.1" }) } } -ArgumentList @($Server))
							If (($CertQuery.Count -eq 1) -and ($CertQuery[0] -ne $null))
							{
								Write-Host "Passed" -ForegroundColor Green
							}
							Else
							{
								Write-Host "Failed" -ForegroundColor Red
								$Validate = $false
							}
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate memory for role
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating memory for roles..."
				Write-Host ""
				$Roles | Where-Object { $_.Existing -ne "True" } | ForEach-Object {
					$RoleValidate = $true
					$Role = $_.Name
					$Server = $_.Server
					If ($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.Memory })
					{
						Write-Host "    Role: $Role... " -NoNewline
						$Memory = [Int64]($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Validation.Memory })
						$MemoryKB = $Memory * 1024
						If ($Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $Role) -and ($_.SQLCluster -ne $null) })
						{
							$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $Server } | ForEach-Object { $_.Node } | ForEach-Object {
								$OSMemory = (Get-WMIObject -Class Win32_OperatingSystem -Namespace root/cimv2 -ComputerName $_.Server -ErrorAction SilentlyContinue).TotalVisibleMemorySize
								If (!($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | Where-Object { $MemoryKB -lt $OSMemory }))
								{
									If ($RoleValidate) { Write-Host "Failed" -ForegroundColor Red }
									Write-Host "      $Memory`MB required for this role" -ForegroundColor Red
									$Validate = $false
									$RoleValidate = $false
								}
							}
						}
						Else
						{
							$OSMemory = (Get-WMIObject -Class Win32_OperatingSystem -Namespace root/cimv2 -ComputerName $Server -ErrorAction SilentlyContinue).TotalVisibleMemorySize
							If (!($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | Where-Object { $MemoryKB -lt $OSMemory }))
							{
								Write-Host "Failed" -ForegroundColor Red
								Write-Host "      $Memory`MB required for this role" -ForegroundColor Red
								$Validate = $false
								$RoleValidate = $false
							}
						}
						If ($RoleValidate)
						{
							Write-Host "Passed" -ForegroundColor Green
						}
					}
				}
				Start-Sleep 1
			}
			
			# Validate DNS for NLB
			If ($Validate)
			{
				Clear-Host
				Write-Host "Validating (Remote)..."
				Write-Host ""
				Write-Host "  Validating DNS entries for NLB roles..."
				Write-Host ""
				$Components = $Workflow.Installer.Roles.Role | Where-Object { $_.Validation.NLB -eq "True" } | ForEach-Object { $_.Component } | Sort-Object -Unique
				$Components | ForEach-Object {
					$Component = $_
					$Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
						Set-ScriptVariable -Name $_.Name -Value $_.Value
					}
					$Variable.Installer.Components.Component | Where-Object { $_.Name -eq $Component } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
						Set-ScriptVariable -Name $_.Name -Value $_.Value
					}
				}
				$Roles | Where-Object { $_.Existing -ne "True" } | ForEach-Object {
					$Role = $_.Name
					If ((Invoke-Expression ("$" + $Role.Replace(" ", "") + "NLBConfig")) -eq "True")
					{
						Write-Host "    Role: $Role... " -NoNewline
						$FullName = Invoke-Expression ("$" + $Role.Replace(" ", "") + "NLBName")
						$IP = Invoke-Expression ("$" + $Role.Replace(" ", "") + "NLBIPv4")
						If (((Resolve-DnsName -Type A -Name $FullName).IPAddress | Sort-Object -Unique) -eq $IP)
						{
							Write-Host "Passed" -ForegroundColor Green
						}
						Else
						{
							Write-Host "Failed" -ForegroundColor Red
							Write-Host "      $FullName does not resolve to $IP" -ForegroundColor Red
							$Validate = $false
						}
					}
					Else
					{
						If (((Invoke-Expression ("$" + $Role.Replace(" ", "") + "NLBName")) -ne $null) -and ((Invoke-Expression ("$" + $Role.Replace(" ", "") + "NLBName")) -ne ""))
						{
							$FullName = Invoke-Expression ("$" + $Role.Replace(" ", "") + "NLBName")
							$Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object {
								$RoleServer = $_.Server
								$RoleIP = ((Resolve-DnsName -Type A -Name $RoleServer).IPAddress | Sort-Object -Unique)
							}
							Write-Host "    Role: $Role... " -NoNewline
							If (((Resolve-DnsName -Type A -Name $FullName).IPAddress | Sort-Object -Unique) -eq $RoleIP)
							{
								Write-Host "Passed" -ForegroundColor Green
							}
							Else
							{
								Write-Host "Failed" -ForegroundColor Red
								Write-Host "      $FullName does not resolve to the same IP as $RoleServer - $RoleIP" -ForegroundColor Red
								$Validate = $false
							}
						}
					}
				}
				Start-Sleep 1
			}
		}
	}
}

Write-Host ""
If (!($Validate))
{
	Write-Host "Validation failed" -ForegroundColor Red
	Write-Host ""
	Exit
}

If ($ValidateOnly)
{
	Exit
}
#endregion Validation

#region Initialize
Clear-Host
Write-Host "Initializing..." -ForegroundColor "White"

# Start the central logger job
New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server "Controller" -Message "Start central logger"
$LogJob = Start-Job -Name "Logger" -ScriptBlock {
	$LogFolder = $args[0]
	$LogFile = $args[1]
	While ($true)
	{
		Get-Item "$LogFolder\Log\*.log" | ForEach-Object {
			Get-Content -Path $_ | Add-Content -Path "$LogFolder\$LogFile.log"
			Remove-Item -Path $_
		}
		Start-Sleep 1
	}
} -ArgumentList @($LogFolder, $LogFile)

# Get unique servers
$Servers = @($Variable.Installer.Roles.Role | Where-Object { ($_.Existing -ne "True") -and ($_.SQLCluster -ne "True") } | Sort-Object { $_.Server } -Unique | ForEach-Object { $_.Server })
$SQLClusters = @($Variable.Installer.Roles.Role | Where-Object { ($_.Existing -ne "True") -and ($_.SQLCluster -eq "True") } | ForEach-Object { $_.Server })
$SQLClusters | ForEach-Object {
	$SQLCluster = $_
	$SQLClusterNodes = $Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLCluster } | ForEach-Object { $_.Node.Server }
	$Servers += $SQLClusterNodes
}
$ExistingServers = $Variable.Installer.Roles.Role | Where-Object { $_.Existing -eq "True" } | Sort-Object { $_.Server } -Unique | ForEach-Object { $_.Server }

# Create success markers for existing roles
$Workflow.Installer.Roles.Role | ForEach-Object {
	$Role = $_.Name
	If ($Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $Role) -and ($_.Existing -eq "True") })
	{
		$Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $Role) -and ($_.Existing -eq "True") } | ForEach-Object {
			$Server = $_.Server
			$Role = $Role.Replace(" ", "")
			$true | Out-File "$LogFolder\Temp\$Role.$Server.role"
			$Statusfile = "$LogFolder\Temp\" + $Server + ".status"
			"Existing server" | Out-File $StatusFile
			$Colorfile = "$LogFolder\Temp\" + $Server + ".color"
			"Green" | Out-File $ColorFile
			If ($_.SQLCluster -eq "True")
			{
				$Cluster = $Server
				$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $Cluster } | ForEach-Object { $_.Node } | ForEach-Object {
					$Server = $_.Server
					$true | Out-File "$LogFolder\Temp\$Role.$Server.role"
					$Statusfile = "$LogFolder\Temp\" + $Server + ".status"
					"Existing server" | Out-File $StatusFile
					$Colorfile = "$LogFolder\Temp\" + $Server + ".color"
					"Green" | Out-File $ColorFile
				}
			}
		}
	}
}

# Initialize status
$Servers | ForEach-Object {
	$Server = $_
	$Statusfile = "$LogFolder\Temp\" + $Server + ".status"
	"Initializing..." | Out-File $StatusFile
	$Colorfile = "$LogFolder\Temp\" + $Server + ".color"
	"White" | Out-File $ColorFile
}

# Create fail markers for roles not being installed so dependent roles will fail
$Workflow.Installer.Roles.Role | Where-Object { $_.Type -ne "Integration" } | ForEach-Object {
	$Role = $_.Name
	If (!($Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role }))
	{
		$Role = $Role.Replace(" ", "")
		$false | Out-File "$LogFolder\Temp\$Role.role"
	}
}
#endregion Initialize

#region Per Server
$ServerJobs = @()
$Servers | Sort-Object -Unique | ForEach-Object {
	$Server = $_
	New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server "Controller" -Message "Start server job $Server"
	$ServerJobs += Start-Job -Name $Server -ScriptBlock {
		
		#region Variables
		$Deployment = $args[0]
		$Server = $args[1]
		$LogFolder = $args[2]
		$LogFile = $args[3]
		$Path = $args[4]
		$Mode = $args[5]
		$InstallerStage = $args[6]
		$ServerShort = $Server.Split(".")[0]
		$Global:LogCount = 0
		$StatusFile = "$LogFolder\Temp\" + $Server + ".status"
		$ColorFile = "$LogFolder\Temp\" + $Server + ".color"
		$Global:Success = $true
		$UTCOffset = (New-TimeSpan -Start (Get-Date) -End (Get-Date).ToUniversalTime()).TotalMinutes
		If ($UTCOffset -ge 0) { $UTCOffset = "+" + $UTCOffset }
		#endregion Variables
		
		#region Log and Variable functions...
		Function New-LogEntry ($Deployment, $LogFolder, $LogFile, $Server, $Message, $Status)
		{
			# Writes a single line to a temporary log file to be picked up by the central logger job
			$LogDate = Get-Date -Format MM-dd-yyyy
			$LogTime = Get-Date -Format HH:mm:ss.fff
			#$LogEntry = "$LogDate,$LogTime,$Deployment,$Server," + "{0:D4}" -f $Global:LogCount + ",$Message"
			$LogEntry = "$Message`$`$<$Server><$LogDate $LogTime$UTCOffset><$Deployment>"
			Add-Content -Path "$LogFolder\$Server.log" -Value $LogEntry
			$LogEntry = "{0:D4}" -f $Global:LogCount + "::" + $LogEntry
			Add-Content -Path "$LogFolder\Log\$Server.$Global:LogCount.log" -Value $LogEntry
			If ($Status -and ($Global:Success)) { $Message | Out-File $StatusFile }
			$Global:LogCount++
		}
		
		Function New-LogEntryVariable ($Name, $Value)
		{
			If (!($Name.contains("Password")) -and !($Name.contains("Passphrase")))
			{
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Variable: $Name = $Value"
			}
			Else
			{
				If (($Value -ne $null) -and ($Value -ne ""))
				{
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Variable: $Name = ********"
				}
				Else
				{
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Variable: $Name = "
				}
			}
		}
		
		Function Set-ScriptVariable ($Name, $Value)
		{
			Invoke-Expression ("`$Script:" + $Name + " = `"" + $Value + "`"")
			New-LogEntryVariable -Name $Name -Value (Invoke-Expression("`"$Value`""))
			If (($Name.Contains("ServiceAccount")) -and !($Name.Contains("Password")) -and ($Value -ne ""))
			{
				Invoke-Expression ("`$Script:" + $Name + "Domain = `"$Value`".Split(`"\`")[0]")
				New-LogEntryVariable -Name ($Name + "Domain") -Value (Invoke-Expression("`"$Value`".Split(`"\`")[0]"))
				Invoke-Expression ("`$Script:" + $Name + "Username = `"$Value`".Split(`"\`")[1]")
				New-LogEntryVariable -Name ($Name + "Username") -Value (Invoke-Expression("`"$Value`".Split(`"\`")[1]"))
			}
		}
		#endregion
		
		#region Task Scheduler functions
		Function Connect-TaskService
		{
			# Connect to the task scheduler service
			$Global:TaskService = New-Object -ComObject Schedule.Service
			$TaskServiceConnected = $false
			$TaskServiceTries = 5
			$TaskServiceInterval = 60
			$i = 0
			While ((!($TaskServiceConnected)) -and ($TaskServiceTries -ne $i))
			{
				$i++
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Connecting to task service attempt $i" -Status $true
				$Global:TaskService.Connect($Server, $InstallerServiceAccountUsername, $InstallerServiceAccountDomain, $InstallerServiceAccountPassword)
				If (!(($Global:TaskService.Connected -eq "True") -and ($Global:TaskService.TargetServer -eq $Server)))
				{
					If ($i -eq $TaskServiceTries)
					{
						Fail -Server $Server
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed to connect to task service" -Status $true
					}
					Else
					{
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed to connect to task service" -Status $false
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Waiting $TaskServiceInterval seconds" -Status $false
						Start-Sleep $TaskServiceInterval
					}
				}
				Else
				{
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Connected to task service" -Status $true
					$TaskServiceConnected = $true
				}
			}
			If ($Global:Success) { $Global:TaskFolder = $Global:TaskService.GetFolder("\") }
		}
		
		Function Get-Task ($TaskName)
		{
			# Check to see if a task exists
			$Tasks = $Global:TaskFolder.GetTasks(0)
			Return $Tasks | Where-Object { $_.Name -eq $TaskName }
		}
		
		Function New-Task ($TaskName, $Command, $Arguments, $User, $Password)
		{
			# Create a new task
			$Task = $Global:TaskService.NewTask(0)
			$TaskPrincipal = $Task.Principal
			$TaskPrincipal.RunLevel = 1
			$TaskPrincipal.LogonType = 1
			Switch ($OSVersion.substring(0, 3))
			{
				"6.1" { $Task.Settings.Compatibility = "2" }
				"6.2" { $Task.Settings.Compatibility = "3" }
				"6.3" { $Task.Settings.Compatibility = "4" }
			}
			$TaskAction = $Task.Actions.Create(0)
			$TaskAction.Path = $Command
			$TaskAction.Arguments = $Arguments
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Registering task $TaskName"
			$Global:TaskFolder.RegisterTaskDefinition($TaskName, $Task, 6, $User, $Password, 1)
		}
		Function Start-Task ($TaskName)
		{
			# Start a task
			$Task = $Global:TaskFolder.GetTask($TaskName)
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Starting task $TaskName"
			$Task.Run(0)
		}
		Function Remove-Task ($TaskName)
		{
			# Remove a task
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Removing task $TaskName"
			$Global:TaskFolder.DeleteTask($TaskName, 0)
		}
		#endregion
		
		#region Other functions
		function RebootPending ($Server)
		{
			# ??? Alternate creds ???
			$RebootRequired = $false
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Checking for reboot pending"
			$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Server)
			If ($reg -ne $Null)
			{
				$regKey = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Session Manager")
				If ($regKey -ne $Null)
				{
					If ($regkey.GetValue("PendingFileRenameOperations") -ne $Null)
					{
						$RebootRequired = $true
					}
				}
				$regKey = $reg.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired")
				If ($regKey -ne $Null)
				{
					$RebootRequired = $true
				}
			}
			If ($RebootRequired)
			{
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reboot needed"
				return $True
			}
			Else
			{
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "No reboot needed"
				return $False
			}
		}
		
		function Reboot ($Server)
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Rebooting" -Status $true
			If ($Mode -eq "Build")
			{
				Invoke-Command -Computername $Server { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "VMCreate" -Value "C:\Temp\Setup.bat" }
				Invoke-Command -Computername $Server { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Value 1 }
			}
			$Boottime = [System.Management.ManagementDateTimeconverter]::ToDateTime((Get-WmiObject -Class Win32_OperatingSystem -Namespace root/cimv2 -ComputerName $Server -ErrorAction SilentlyContinue).LastBootUpTime)
			Restart-Computer -ComputerName $Server -Force
			Do
			{
				$WMIBoot = Get-WmiObject -Class Win32_OperatingSystem -Namespace root/cimv2 -ComputerName $Server -ErrorAction SilentlyContinue
				If ($WMIBoot -ne $null)
				{
					$NewBoottime = [System.Management.ManagementDateTimeconverter]::ToDateTime($WMIBoot.LastBootUpTime)
				}
				Start-Sleep 5
			}
			While ($Boottime -eq $NewBoottime)
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Waiting for WinRM" -Status $true
			While (!(Get-WmiObject -Class Win32_Service -Namespace root/cimv2 -ComputerName $Server -ErrorAction SilentlyContinue | Where-Object { ($_.Name -eq "WinRM") -and ($_.State -eq "Running") }))
			{
				Start-Sleep 5
			}
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reboot complete" -Status $true
			Connect-TaskService
		}
		
		function Copy-Source ($SourceName, $Source, $Destination)
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Copying source $SourceName" -Status $true
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Copying source from $Source to $Destination"
			Start-Process -FilePath "robocopy.exe" -ArgumentList "$Source $Destination /e" -Wait -WindowStyle Hidden
		}
		
		Function Set-Firewall ($Server, $FWName, $FWType, $FWValue)
		{
			Invoke-Command -ComputerName $Server -ScriptBlock {
				$FWName = $Args[0]
				$FWType = $Args[1]
				$FWValue = $Args[2]
				$Firewall = New-Object -ComObject HNetCfg.FWPolicy2
				If (!($Firewall.Rules | Where-Object { ($_.Name -eq $FWName) -and ($_.Grouping -eq "Installer") }))
				{
					$Rule = New-Object -ComObject HNetCfg.FWRule
					$Rule.Name = $FWName
					Switch ($FWType)
					{
						"Application" { $Rule.ApplicationName = $FWValue }
						"Service" {
							$Rule.ServiceName = $FWValue.Split("/")[0]
							$Rule.ApplicationName = $FWValue.Split("/")[1]
						}
						"Port" {
							Switch ($FWValue.Split("/")[0])
							{
								"TCP" { $Rule.Protocol = 6 }
							}
							$Rule.LocalPorts = $FWValue.Split("/")[1]
						}
					}
					$Rule.Enabled = $True
					$Rule.Grouping = "Installer"
					$Rule.Profiles = 7
					$Rule.Action = 1
					$Firewall.Rules.Add($Rule)
				}
			} -ArgumentList @($FWName, $FWType, $FWValue)
		}
		
		function Validate ($Server, $Type, $Value)
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Validation: $Type $Value"
			Switch ($Type)
			{
				"ProductCode" {
					$Result = $False
					@($Value.Split("/")) | ForEach-Object {
						$SearchCode = $_
						If (Get-WMIObject -Class Win32_Product -Namespace root/cimv2 -ComputerName $Server | Where-Object { $_.IdentifyingNumber -eq $SearchCode }) { $Result = $true }
					}
					Return $Result
				}
				"ProductCodeVersion" {
					$Result = $False
					@($Value.Split("/")) | ForEach-Object {
						$SearchCode = $_.Split("}")[0] + "}"
						$SearchVersion = $_.Split("}")[1]
						If (Get-WMIObject -Class Win32_Product -Namespace root/cimv2 -ComputerName $Server | Where-Object { ($_.IdentifyingNumber -eq $SearchCode) -and ($_.Version -eq $SearchVersion) }) { $Result = $true }
					}
					Return $Result
				}
				"Service" { If (Get-WMIObject -Class Win32_Service -Namespace root/cimv2 -ComputerName $Server | Where-Object { $_.Name -eq $Value }) { return $True } }
				"ServiceRunning" { If (Get-WMIObject -Class Win32_Service -Namespace root/cimv2 -ComputerName $Server | Where-Object { ($_.Name -eq $Value) -and ($_.State -eq "Running") }) { return $True } }
				"Cluster" { If (Get-WMIObject -Class MSCluster_ResourceGroup -Namespace root/mscluster -ComputerName $Server | Where-Object { $_.Name -eq $Value }) { return $True } }
				"QFE" { If (Get-WMIObject -Class Win32_QuickFixEngineering -Namespace root/cimv2 -ComputerName $Server | Where-Object { $_.HotFixID -eq $Value }) { return $True } }
				"RegKey" {
					$RegObject = Get-WMIObject -List -Namespace root\default -ComputerName $server | Where-Object { $_.Name -eq "StdRegProv" }
					$RegKeys = $RegObject.EnumKey(2147483650, $Value)
					If ($RegKeys.sNames.Count -gt 0) { Return $True }
				}
				"RegValue" {
					$RegKey = $Value.Split("=")[0]
					$RegEntry = $RegKey.Split(",")[1]
					$RegKey = $RegKey.Split(",")[0]
					$RegValue = $Value.Split("=")[1]
					Return (Invoke-Command -ComputerName $Server {
						$RegKey = $args[0]
						$RegEntry = $args[1]
						$RegValue = $args[2]
						If ((Get-ItemProperty "HKLM:$RegKey").$RegEntry -eq $RegValue)
						{
							Return $true
						}
						Else
						{
							Return $false
						}
					} -ArgumentList @($RegKey, $RegEntry, $RegValue))
				}
				"TestPath" {
					$FExists = "\\" + $Server + "\" + $Value.Replace(":", "$")
					If (Test-Path $FExists) { return $True }
				}
				"UserInGroup" {
					$User = $Value.Split("/")[0]
					$Group = $Value.Split("/")[1]
					$Group = [ADSI]("WinNT://$Server/$Group,group")
					Return (Get-UserInGroup -User $User -Group $Group)
				}
				"Powershell" {
					Return (Invoke-Command -ComputerName $Server -ScriptBlock { $Value = $args[0]; Invoke-Expression($Value) } -ArgumentList @($Value))
				}
				"None" { Return $False }
			}
		}
		
		function Invoke-Install ($Server, $Install)
		{
			# Create command line
			$Install.CommandLines.CommandLine | ForEach-Object {
				$Command = ""
				$Argument = ""
				$Reboot = $_.Reboot
				$Condition = $False
				If ($_.Condition -ne $null)
				{
					Invoke-Expression ("If (" + $_.Condition + ") {`$Condition = `$True}")
				}
				Else { $Condition = $True }
				If ($Condition)
				{
					# Create INI file
					$_.INIFile | ForEach-Object {
						$INIFile = @()
						$_.Section | Where-Object { $_.Name -ne $Null } | ForEach-Object {
							$INISection = "[" + $_.Name + "]"
							New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "INIFile: $INISection"
							$INIFile = $INIFile + $INISection
							$_.Entry | Where-Object { $_.Value -ne $Null } | ForEach-Object {
								If ($_.Condition -eq $Null)
								{
									$Condition = $True
								}
								Else
								{
									Invoke-Expression ("If (" + $_.Condition + ") {`$Condition = `$True} Else {`$Condition = `$False}")
								}
								If ($Condition)
								{
									Invoke-Expression ("`$INIFile = `$INIFile + " + "`"" + $_.Value + "`" ")
									If ($_.Log -eq $Null)
									{
										Invoke-Expression ("`$Message = " + "`"" + $_.Value + "`" ")
									}
									Else
									{
										Invoke-Expression ("`$Message = " + "`"" + $_.Log + "`" ")
									}
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "INIFile: $Message"
								}
							}
							$INIFile = $INIFile + ""
						}
						$INIFile | Out-File "\\$Server\$TempPathUNC\Installer.ini" -Encoding ASCII
					}
					# Create answer file
					$_.AnswerFile | ForEach-Object {
						$AnswerFile = @()
						$_.Entry | Where-Object { $_.Value -ne $Null } | ForEach-Object {
							If ($_.Condition -eq $Null)
							{
								$Condition = $True
							}
							Else
							{
								Invoke-Expression ("If (" + $_.Condition + ") {`$Condition = `$True} Else {`$Condition = `$False}")
							}
							If ($Condition)
							{
								Invoke-Expression ("`$AnswerFile = `$AnswerFile + " + "`"" + $_.Value + "`" ")
								If ($_.Log -eq $Null)
								{
									Invoke-Expression ("`$Message = " + "`"" + $_.Value + "`" ")
								}
								Else
								{
									Invoke-Expression ("`$Message = " + "`"" + $_.Log + "`" ")
								}
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "AnswerFile: $Message"
							}
						}
						$AnswerFile | Out-File "\\$Server\$TempPathUNC\Installer.txt" -Encoding ASCII
					}
					# Create command line
					Invoke-Expression ("`$Command = " + "`"" + $_.Executable + "`"")
					Invoke-Expression ("`$CommandLineLog = " + "`"" + $_.Executable + "`"")
					$_.Switches | Where-Object { $_.Switch -ne $null } | ForEach-Object { $_.Switch } | Where-Object { $_.Value -ne $null } | ForEach-Object {
						If ($_.Condition -eq $null)
						{
							$Condition = $True
						}
						Else
						{
							Invoke-Expression ("If (" + $_.Condition + ") {`$Condition = `$True} Else {`$Condition = `$False}")
						}
						If ($Condition)
						{
							Invoke-Expression ("`$Argument = `$Argument + " + "`" " + $_.Value + "`" ")
							If ($_.Log -eq $null)
							{
								Invoke-Expression ("`$CommandLineLog = `$CommandLineLog + " + "`" " + $_.Value + "`" ")
							}
							Else
							{
								Invoke-Expression ("`$CommandLineLog = `$CommandLineLog + " + "`" " + $_.Log + "`" ")
							}
						}
					}
					If ($Command -ne "")
					{
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Command: $CommandLineLog"
						If ($_.Workaround -ne $null)
						{
							Invoke-Expression ("`$Workaround = `"" + $_.Workaround + "`"")
							New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Workaround: $Workaround"
						}
						Else
						{
							$Workaround = $null
						}
						"$Command $Argument" | Out-File "\\$Server\$TempPathUNC\Installer.bat" -Encoding ASCII
						If ($Install.Log -ne $null)
						{
							If ($Install.LogFile -ne $null)
							{
								$LogCopy = "robocopy.exe `"" + $Install.Log + "`" `"" + $TempPath + "\Installer\" + $Deployment + "\" + $Install.Name + "`" " + $Install.LogFile
							}
							Else
							{
								$LogCopy = "robocopy.exe `"" + $Install.Log + "`" `"" + $TempPath + "\Installer\" + $Deployment + "\" + $Install.Name + "`" /e"
							}
							$LogCopy | Out-File "\\$Server\$TempPathUNC\Installer.bat" -Encoding ASCII -Append
						}
						# Execute install
						$TaskName = [guid]::NewGuid().ToString()
						New-Task $TaskName "cmd.exe" "/c $TempPath\Installer.bat" $InstallerServiceAccount $InstallerServiceAccountPassword | Out-Null
						Start-Task $TaskName | Out-Null
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Checking that task $TaskName has started"
						Start-Sleep 10
						$TaskStarted = $false
						While ($TaskStarted -eq $false)
						{
							@(Get-Task -TaskName $TaskName) | ForEach-Object {
								If ($_.LastRunTime.Year -eq (Get-Date).Year) { $TaskStarted = $true }
							}
						}
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Task $TaskName has started"
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Waiting for task $TaskName to complete"
						While (((Get-Task $TaskName) -eq $null) -or ((Get-Task $TaskName).State -eq "4"))
						{
							If ($Workaround -ne $null)
							{
								Invoke-Expression ($Workaround)
							}
							Start-Sleep 1
						}
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Task $TaskName has completed"
						Remove-Task $TaskName
						If (Test-Path "\\$Server\$TempPathUNC\Installer.ini") { Remove-Item -Path "\\$Server\$TempPathUNC\Installer.ini" }
						If (Test-Path "\\$Server\$TempPathUNC\Installer.txt") { Remove-Item -Path "\\$Server\$TempPathUNC\Installer.txt" }
						Remove-Item -Path "\\$Server\$TempPathUNC\Installer.bat"
						If ($Reboot -or (RebootPending -Server $Server))
						{
							New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$InstallName requires a restart" -Status $true
							If ($ServerShort -eq $env:ComputerName)
							{
								Fail -Server $Server
							}
							Else
							{
								Reboot -Server $Server
							}
						}
					}
				}
			}
			If ($Global:Success)
			{
				$Install.Firewall.Rule | Where-Object { $_ -ne $null } | ForEach-Object {
					$Condition = $False
					If ($_.Condition -ne $null)
					{
						Invoke-Expression ("If (" + $_.Condition + ") {`$Condition = `$True}")
					}
					Else { $Condition = $True }
					If ($Condition)
					{
						Invoke-Expression ("`$FWName = " + "`"" + $_.Name + "`"")
						Invoke-Expression ("`$FWType = " + "`"" + $_.Type + "`"")
						Invoke-Expression ("`$FWValue = " + "`"" + $_.Value + "`"")
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Firewall: $FWName,$FWType,$FWValue"
						Set-Firewall -Server $Server -FWName $FWName -FWType $FWType -FWValue $FWValue
					}
				}
			}
		}
		
		Function Fail ($Server)
		{
			$Global:Success = $False
			"Red" | Out-File $ColorFile
			$Roles | ForEach-Object {
				$FailRole = $_
				$Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $FailRole) -and ($_.SQLCluster -eq "True") } | Where-Object { $_ -ne $null } | ForEach-Object {
					$FailRole = $FailRole.Replace(" ", "")
					$Cluster = $_.Server
					$Global:Success | Out-File "$LogFolder\Temp\$FailRole.$Cluster.role"
				}
				$Role = $_.Replace(" ", "")
				If (!(Test-Path "$LogFolder\Temp\$Role.$Server.role"))
				{
					$Global:Success | Out-File "$LogFolder\Temp\$Role.$Server.role"
				}
			}
		}
		
		Function Get-UserInGroup ($User, $Group)
		{
			$Group.Members() | ForEach-Object {
				$AdsPath = $_.GetType().InvokeMember("Adspath", 'GetProperty', $Null, $_, $Null)
				$A = $AdsPath.split('/', [StringSplitOptions]::RemoveEmptyEntries)
				$Name = $A[2]
				$Domain = $A[1]
				$Class = $_.GetType().InvokeMember("Class", 'GetProperty', $Null, $_, $Null)
				if ((($Class -eq "User") -or ($Class -eq "Group")) -and ($Domain -eq $User.Split("\")[0]) -and ($Name -eq $User.Split("\")[1])) { return $True }
			}
		}
		#endregion Other functions
		
		#region Input, variables, roles & integrations, server info
		New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Start $Server" -Status $true
		# Read input files
		New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading input files"
		$Workflow = [XML] (Get-Content "$Path\Workflow.xml")
		If (Test-Path "$Path\Extender*.xml")
		{
			Get-ChildItem -Path "$Path\Extender*.xml" | ForEach-Object {
				$ExtenderFile = $_.Name
				$Extender = [XML] (Get-Content "$Path\$ExtenderFile")
				$Extender.Installer.ServerFeatures | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderServerFeaturesOSVersion = $_.OSVersion
					$_.Group | Where-Object { $_ -ne $null } | ForEach-Object {
						$ExtenderServerFeaturesGroup = $_.Name
						$_.ServerFeature | Where-Object { $_ -ne $null } | ForEach-Object {
							$ExtenderServerFeature = $_
							If (!($Workflow.Installer.ServerFeatures | Where-Object { $_.OSVersion -eq $ExtenderServerFeaturesOSVersion } | ForEach-Object { $_.Group } | Where-Object { $_.Name -eq $ExtenderServerFeaturesGroup } | ForEach-Object { $_.ServerFeature } | Where-Object { $_.Name -eq $ExtenderServerFeature.Name }))
							{
								($Workflow.Installer.ServerFeatures | Where-Object { $_.OSVersion -eq $ExtenderServerFeaturesOSVersion } | ForEach-Object { $_.Group } | Where-Object { $_.Name -eq $ExtenderServerFeaturesGroup }).AppendChild($Workflow.ImportNode($ExtenderServerFeature, $true)) | Out-Null
							}
						}
					}
				}
				$Extender.Installer.Installables.Installable | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderInstallable = $_
					If (!($Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $ExtenderInstallable.Name }))
					{
						$Workflow.Installer.Installables.AppendChild($Workflow.ImportNode($ExtenderInstallable, $true)) | Out-Null
					}
				}
				$Extender.Installer.Components.Component | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderComponent = $_
					If (!($Workflow.Installer.Components.Component | Where-Object { $_.Name -eq $ExtenderComponent.Name }))
					{
						$Workflow.Installer.Components.AppendChild($Workflow.ImportNode($ExtenderComponent, $true)) | Out-Null
					}
				}
				$Extender.Installer.SQL.SQL | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderSQL = $_
					If (!($Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $ExtenderSQL.Version }))
					{
						$Workflow.Installer.SQL.AppendChild($Workflow.ImportNode($ExtenderSQL, $true)) | Out-Null
					}
				}
				$Extender.Installer.Roles.Role | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderRole = $_
					If (!($Workflow.Installer.Role.Role | Where-Object { $_.Name -eq $ExtenderRole.Name }))
					{
						$Workflow.Installer.Roles.AppendChild($Workflow.ImportNode($ExtenderRole, $true)) | Out-Null
					}
				}
				$Extender.Installer.Integrations.Integration | Where-Object { $_ -ne $null } | ForEach-Object {
					$ExtenderIntegration = $_
					If (!($Workflow.Installer.Integrations.Integration | Where-Object { $_.Name -eq $ExtenderIntegration.Name }))
					{
						$Workflow.Installer.Integrations.AppendChild($Workflow.ImportNode($ExtenderIntegration, $true)) | Out-Null
					}
				}
			}
		}
		$Variable = [XML] (Get-Content "$Path\Variable.xml")
		
		# Get variables
		# Global
		New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading global variables from workflow.xml"
		$Workflow.Installer | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
			Set-ScriptVariable -Name $_.Name -Value $_.Value
		}
		New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading global variables from variable.xml"
		$Variable.Installer | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
			Set-ScriptVariable -Name $_.Name -Value $_.Value
		}
		
		# Get roles for this server
		New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Getting roles" -Status $true
		$Roles = @($Variable.Installer.Roles.Role | Where-Object { $_.Server -eq $Server } | Where-Object { $_.Existing -ne "True" } | ForEach-Object { $_.Name })
		$Roles | ForEach-Object { New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Role: $_" }
		
		# Get SQL cluster roles for this server
		New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Getting SQL cluster roles" -Status $true
		$Variable.Installer.SQL.Cluster | ForEach-Object {
			$SQLCluster = $_.Cluster
			$_.Node | Where-Object { $_.Server -eq $Server } | ForEach-Object {
				$SQLClusterNode = $_.Server
				$SQLClusterNodes = $Variable.Installer.Roles.Role | Where-Object { $_.Server -eq $SQLCluster } | ForEach-Object { $_.Name }
				$SQLClusterNodes | ForEach-Object { New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "SQL cluster $SQLCluster role: $_" }
				$Roles += $SQLClusterNodes
			}
		}
		
		# Get integrations for this server
		If ($InstallerStage -ge 7)
		{
			# For each role on this server...
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Getting integrations" -Status $true
			$Roles | ForEach-Object {
				$Role = $_
				$Integration = $false
				# ...find integrations targeted at that role
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Getting integrations for role $Role"
				$Workflow.Installer.Integrations.Integration | Where-Object { $_.Target -eq $Role } | ForEach-Object {
					$ThisIntegration = $_.Name
					$Integration = $true
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Checking dependencies for integration $ThisIntegration"
					# Check that all integration dependencies exist in this deployment
					$_.Dependency | ForEach-Object {
						$Dependency = $_
						If (!($Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Dependency }))
						{
							$Integration = $false
							New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Integration dependency $Dependency does not exist in this deployment"
						}
						Else
						{
							New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Integration dependency $Dependency exists in this deployment"
						}
					}
					If ($Integration)
					{
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Integration: $ThisIntegration"
						$Roles += $ThisIntegration
					}
				}
			}
		}
		Else
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Skipping installer stage 7 - Integrations"
		}
		
		# Get server info
		New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Getting server information" -Status $true
		$OS = Get-WMIObject -Class Win32_OperatingSystem -Namespace root/cimv2 -ComputerName $Server -ErrorAction SilentlyContinue
		If ($OS -eq $Null)
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed to get server information" -Status $true
			Fail -Server $Server
		}
		Else
		{
			$OSVersion = $OS.Version
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "OS Version: $OSVersion"
			$SystemDrive = $OS.SystemDrive
			$SystemDriveUNC = $SystemDrive.Replace(":", "$")
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "System Drive: $SystemDrive"
			$WinDir = $OS.WindowsDirectory
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Windows Directory: $WinDir"
			$Language = $OS.OSLanguage
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Language: $Language"
			$Locale = $OS.Locale
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Locale: $Locale"
			$AdminGroup = (Get-WMIObject Win32_Group -filter "LocalAccount=True AND SID='S-1-5-32-544'" -ComputerName $Server).Name
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Administrators Group: $AdminGroup"
			$Group = [ADSI]("WinNT://$Server/$AdminGroup,group")
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Getting potential SSL certificate" -Status $true
			$CertQuery = @(Invoke-Command -ComputerName $Server -ScriptBlock { $Server = $args[0]; If (!(Get-Module PKI)) { Import-Module PKI -ErrorAction SilentlyContinue }; If (Get-Module PKI) { Return (Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { ($_.Subject -eq "CN=$Server") -and ($_.Issuer -ne "CN=$Server") } | Where-Object { $_.EnhancedKeyUsageList.ObjectId -eq "1.3.6.1.5.5.7.3.1" }) } } -ArgumentList @($Server))
			If (($CertQuery.Count -eq 1) -and ($CertQuery[0] -ne $null))
			{
				$SSLCert = $CertQuery[0].Thumbprint
				$SSLCertSerialNumber = $CertQuery[0].SerialNumber
				$SSLCertIssuer = $CertQuery[0].Issuer
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Found certificate issued by $SSLCertIssuer"
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "SSL certificate thumbprint is $SSLCert"
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "SSL certificate serial number is $SSLCertSerialNumber"
				$SSLCert | Out-File "$LogFolder\Temp\$Server.cert"
			}
			Else
			{
				$CertQuery = @(Invoke-Command -ComputerName $Server -ScriptBlock { $Server = $args[0]; If (!(Get-Module PKI)) { Import-Module PKI -ErrorAction SilentlyContinue }; If (Get-Module PKI) { Return (Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { ($_.Subject -eq "CN=$Server") -and ($_.Issuer -eq "CN=$Server") } | Where-Object { $_.EnhancedKeyUsageList.ObjectId -eq "1.3.6.1.5.5.7.3.1" }) } } -ArgumentList @($Server))
				If (($CertQuery.Count -eq 1) -and ($CertQuery[0] -ne $null))
				{
					$SSLCert = $CertQuery[0].Thumbprint
					$SSLCertSerialNumber = $CertQuery[0].SerialNumber
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Found self-signed certificate"
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "SSL certificate thumbprint is $SSLCert"
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "SSL certificate serial number is $SSLCertSerialNumber"
					$SSLCert | Out-File "$LogFolder\Temp\$Server.cert"
				}
				Else
				{
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "No suitable SSL certificate found"
				}
			}
		}
		
		If ($Global:Success)
		{
			# Get variables again - with server info this time
			# Global
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading global variables with server info from workflow.xml"
			$Workflow.Installer | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
				Set-ScriptVariable -Name $_.Name -Value $_.Value
			}
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading global variables with server info from variable.xml"
			$Variable.Installer | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
				Set-ScriptVariable -Name $_.Name -Value $_.Value
			}
			# Source
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading installables variables from workflow.xml"
			$Workflow.Installer.Installables.Installable | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
				Set-ScriptVariable -Name $_.Name -Value $_.Value
			}
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading installables variables from variable.xml"
			$Variable.Installer.Installables.Installable | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
				Set-ScriptVariable -Name $_.Name -Value $_.Value
			}
			# If multiples and this server is one, set to this server
			$Workflow.Installer.Roles.Role | ForEach-Object {
				$Role = $_.Name
				$Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | Sort-Object { $_.Server } -Descending | ForEach-Object {
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading role server variables from variable.xml"
					Set-ScriptVariable -Name $_.Name.Replace(" ", "") -Value $_.Server
					Set-ScriptVariable -Name ($_.Name.Replace(" ", "") + "Short") -Value $_.Server.Split(".")[0]
					Set-ScriptVariable -Name ($_.Name.Replace(" ", "") + "Domain") -Value $_.Server.Split(".")[1]
					If ($_.Instance -ne $Null)
					{
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading role server instance variables from variable.xml"
						Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "Instance") -Value $_.Instance
						$ServerX = $_.Server
						$InstanceX = $_.Instance
						If ($_.SQLCluster -ne "True")
						{
							$SQLVersion = $Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $ServerX) -and ($_.Instance -eq $InstanceX) } | ForEach-Object { $_.Version }
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "Version") -Value $SQLVersion
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLServiceAccount") -Value ($Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $ServerX) -and ($_.Instance -eq $InstanceX) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLServiceAccount" }).Value
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLServiceAccountPassword") -Value ($Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $ServerX) -and ($_.Instance -eq $InstanceX) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLServiceAccountPassword" }).Value
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLASServiceAccount") -Value ($Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $ServerX) -and ($_.Instance -eq $InstanceX) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLASServiceAccount" }).Value
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLASServiceAccountPassword") -Value ($Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $ServerX) -and ($_.Instance -eq $InstanceX) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLASServiceAccountPassword" }).Value
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLAgtServiceAccount") -Value ($Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $ServerX) -and ($_.Instance -eq $InstanceX) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLAgtServiceAccount" }).Value
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLAgtServiceAccountPassword") -Value ($Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $ServerX) -and ($_.Instance -eq $InstanceX) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLAgtServiceAccountPassword" }).Value
							If (($Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $ServerX) -and ($_.Instance -eq $InstanceX) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLSAPassword" }).Value -ne $null)
							{
								Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLSAPassword") -Value ($Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $ServerX) -and ($_.Instance -eq $InstanceX) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLSAPassword" }).Value
							}
							Else
							{
								Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLSAPassword") -Value (Invoke-Expression (($Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLSAPassword" }).Value))
							}
							$SQLPort = $Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $ServerX) -and ($_.Instance -eq $InstanceX) } | ForEach-Object { $_.Port }
							If ($SQLPort -ne $null)
							{
								Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "Port") -Value $SQLPort
							}
							Else
							{
								Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "Port") -Value "1433"
							}
						}
					}
					If ($_.SQLCluster -eq "True")
					{
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading role server cluster variables from variable.xml"
						$ClusterX = $_.Server
						$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Node } | Where-Object { $_.Preferred -eq "1" } | ForEach-Object {
							Set-ScriptVariable -Name $Role.Replace(" ", "").Replace("Server", "Node") -Value $_.Server
						}
						$SQLVersion = $Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Version }
						Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "Version") -Value $SQLVersion
						Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLServiceAccount") -Value ($Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLServiceAccount" }).Value
						Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLServiceAccountPassword") -Value ($Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLServiceAccountPassword" }).Value
						Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLASServiceAccount") -Value ($Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLASServiceAccount" }).Value
						Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLASServiceAccountPassword") -Value ($Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLASServiceAccountPassword" }).Value
						Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLAgtServiceAccount") -Value ($Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLAgtServiceAccount" }).Value
						Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLAgtServiceAccountPassword") -Value ($Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLAgtServiceAccountPassword" }).Value
						If (($Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLSAPassword" }).Value -ne $null)
						{
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLSAPassword") -Value ($Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLSAPassword" }).Value
						}
						Else
						{
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "SQLSAPassword") -Value (Invoke-Expression (($Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -eq "SQLSAPassword" }).Value))
						}
						$SQLPort = $Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $ClusterX } | ForEach-Object { $_.Port }
						If ($SQLPort -ne $null)
						{
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "Port") -Value $SQLPort
						}
						Else
						{
							Set-ScriptVariable -Name $_.Name.Replace(" ", "").Replace("Server", "Port") -Value "1433"
						}
					}
				}
				If ($Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $Role) -and ($_.Server -eq $Server) })
				{
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading role server specific variables from variable.xml"
					Set-ScriptVariable -Name $Role.Replace(" ", "") -Value $Server
					Set-ScriptVariable -Name ($Role.Replace(" ", "") + "Short") -Value $Server.Split(".")[0]
				}
			}
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading component variables from workflow.xml"
			$Workflow.Installer.Components.Component | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
				Set-ScriptVariable -Name $_.Name -Value $_.Value
			}
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading component variables from variable.xml"
			$Variable.Installer.Components.Component | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
				Set-ScriptVariable -Name $_.Name -Value $_.Value
			}
			$TempPathUNC = $TempPath.Replace(":", "$")
			If (!(Test-Path "\\$Server\$TempPathUNC")) { New-Item "\\$Server\$TempPathUNC" -ItemType Directory }
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "TempPath: $TempPath"
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "TempPathUNC: $TempPathUNC"
		}
		
		#endregion Input, variables, roles & integrations
		
		#region Check WinRM and Task Scheduler
		If (RebootPending -Server $Server)
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$Server requires a restart" -Status $true
			If ($ServerShort -eq $env:ComputerName)
			{
				Fail -Server $Server
			}
			Else
			{
				Reboot -Server $Server
			}
		}
		If ($Global:Success)
		{
			
			# Check WinRM service
			If ($Server.Split(".")[0] -ne $env:ComputerName)
			{
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Waiting for WinRM" -Status $true
				While (!(Get-WmiObject -Class Win32_Service -Namespace root/cimv2 -ComputerName $Server | Where-Object { ($_.Name -eq "WinRM") -and ($_.State -eq "Running") }))
				{
					Start-Sleep 5
				}
			}
			
			Connect-TaskService
			
		}
		#endregion Check WinRM and Task Scheduler
		
		#region Admins
		If ($InstallerStage -ge 1)
		{
			If ($Global:Success)
			{
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Start administrators" -Status $true
				$Roles | ForEach-Object {
					$Role = $_
					# Get roles on this server that need an admin
					$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Admin } | Where-Object { $_ -ne $null } | ForEach-Object {
						Invoke-Expression ("`$User = `"`$" + $_.Account + "`"")
						If (($User -ne $Server) -and ($User -ne "LocalSystem") -and ($User -ne ""))
						{
							If ($_.Type -eq "Computer")
							{
								$User = $User.Split(".")[1] + "\" + $User.Split(".")[0] + "`$"
							}
							$UserPath = "WinNT://" + $User.Split("\")[0] + "/" + $User.Split("\")[1]
							Try { $TestUser = [ADSI]::Exists("$UserPath") }
							Catch { $TestUser = $false }
							If ($TestUser)
							{
								If (Get-UserInGroup -User $User -Group $Group)
								{
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "User $User is already member of $AdminGroup" -Status $true
								}
								Else
								{
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Adding user $User to $AdminGroup" -Status $true
									$GroupPath = "WinNT://" + $Server + "/" + $AdminGroup + ",group"
									$UserPath = "WinNT://" + $User.Split("\")[0] + "/" + $User.Split("\")[1]
									([ADSI]$GroupPath).Add($UserPath)
									If (Get-UserInGroup -User $User -Group $Group)
									{
										New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "User $User added to $AdminGroup" -Status $true
									}
									Else
									{
										"Red" | Out-File $ColorFile
										New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed adding user $User to $AdminGroup" -Status $true
										Fail -Server $Server
									}
								}
							}
							Else
							{
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "User $User does not exist - skipping admin group" -Status $true
							}
						}
					}
				}
				If ($Global:Success) { New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "End administrators" -Status $true }
			}
		}
		Else
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Skipping installer stage 1 - Admins"
		}
		#endregion Admins
		
		#region Server Features
		If ($InstallerStage -ge 2)
		{
			If ($Global:Success)
			{
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Start server features" -Status $true
				$ServerFeaturesValidate = $false
				("Install", "Validate") | ForEach-Object {
					$Pass = $_
					If (($Pass -eq "Install") -or (($Pass -eq "Validate") -and $ServerFeaturesValidate))
					{
						If ($Global:Success)
						{
							# Install server features by group
							Start-Sleep 5
							$Workflow.Installer.ServerFeatures | Where-Object { $_.OSVersion -eq $OSVersion } | ForEach-Object { $_.Group } | ForEach-Object {
								If ($Global:Success)
								{
									$Group = $_.Name
									$ServerFeaturesInstall = ""
									$ServerFeaturesSource = $_.Source
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$Pass server features group $Group" -Status $true
									# For each server feature...
									$Workflow.Installer.ServerFeatures | Where-Object { $_.OSVersion -eq $OSVersion } | ForEach-Object { $_.Group } | Where-Object { $_.Name -eq $Group } | ForEach-Object { $_.ServerFeature } | ForEach-Object {
										$ServerFeature = $_
										$ServerFeatureName = $_.Name
										$ServerFeatureRequired = $false
										# ...check if any role requires it
										$Roles | ForEach-Object {
											$Role = $_
											$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.ServerFeatures } | Where-Object { $_.OSVersion -eq $OSVersion } | ForEach-Object { $_.ServerFeature } | Where-Object { $_.Name -eq $ServerFeatureName } | ForEach-Object {
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Server feature $ServerFeatureName is required for $Role"
												$ServerFeatureRequired = $true
											}
										}
										# If it's required, check to see if it's installed
										If ($ServerFeatureRequired)
										{
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Server feature $ServerFeatureName is required" -Status $true
											# If it's not installed, add the install string
											If (!(Get-WMIObject -Class Win32_ServerFeature -Namespace root/cimv2 -ComputerName $Server | Where-Object { $_.ID -eq $ServerFeature.Validation }))
											{
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Server feature $ServerFeatureName is not installed" -Status $true
												$ServerFeaturesValidate = $true
												If ($Pass -eq "install")
												{
													If ($ServerFeaturesInstall -eq "")
													{
														$ServerFeaturesInstall = $ServerFeature.Install
													}
													Else
													{
														$ServerFeaturesInstall = $ServerFeaturesInstall + "," + $ServerFeature.Install
													}
												}
												Else
												{
													New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed server feature $ServerFeatureName" -Status $true
													Fail -Server $Server
												}
											}
											Else
											{
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Server feature $ServerFeatureName is installed" -Status $true
											}
										}
									}
									# If required, install server features
									If ($Global:Success)
									{
										If ($ServerFeaturesInstall -ne "")
										{
											If ($ServerFeaturesSource -ne $null)
											{
												Invoke-Expression ("`$ServerFeaturesSource = `"" + $ServerFeaturesSource + "`"")
												Copy-Source -SourceName "server features" -Source "$SourcePath\$ServerFeaturesSource" -Destination "\\$Server\$TempPathUNC\Installer\$ServerFeaturesSource"
												$ServerFeaturesSource = " -Source $TempPath\Installer\$ServerFeaturesSource"
											}
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Installing server features group $Group" -Status $true
											$Command = "If (!(Get-Module ServerManager)) {Import-Module ServerManager};Add-WindowsFeature $ServerFeaturesInstall $ServerFeaturesSource"
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Command: $Command"
											$ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Command)
											$ServerFeaturesResult = Invoke-Command -ComputerName $Server -ScriptBlock $ScriptBlock
											# Check exit codes
											If (!($ServerFeaturesResult.Success))
											{
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed installing server feature group $Group" -Status $true
												Fail -Server $Server
											}
											If ($ServerFeaturesResult.RestartNeeded -eq "Yes")
											{
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Server feature group $Group requires a restart" -Status $true
												If ($ServerShort -eq $env:ComputerName)
												{
													Fail -Server $Server
												}
												Else
												{
													Reboot -Server $Server
												}
											}
										}
									}
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "End server features group $Group" -Status $true
								}
							}
						}
					}
				}
				If ($Global:Success) { New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "End server features" -Status $true }
			}
		}
		Else
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Skipping installer stage 2 - ServerFeatures"
		}
		#endregion Server Features
		
		#region SQL clusters
		If ($InstallerStage -ge 3)
		{
			If ($Global:Success)
			{
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Start SQL clusters" -Status $true
				# Get unique SQL clusters for this server
				$SQLClusters = $Variable.Installer.Roles.Role | Where-Object { ($_.Existing -ne "True") -and ($_.SQLCluster -eq "True") } | Sort-Object { $_.Server } -Unique | ForEach-Object { $_.Server }
				$SQLClusters | ForEach-Object {
					$SQLCluster = $_
					$SQLClusterShort = $SQLCluster.split(".")[0]
					$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLCluster } | ForEach-Object {
						If ($_.Node.Server -eq $Server)
						{
							If ($Global:Success)
							{
								$SQLVersion = $Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLCluster } | ForEach-Object { $_.Version }
								$SQLPort = $Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLCluster } | ForEach-Object { $_.Port }
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "SQL cluster $SQLCluster version is $SQLVersion" -Status $true
								$SQLClusterNodes = $Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLCluster } | ForEach-Object { $_.Node } | ForEach-Object { $_.Server }
								$SQLClusterNodes | ForEach-Object { New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "SQL cluster $SQLCluster node: $_" -Status $true }
								# Get SQL instance for cluster
								$Instance = $Variable.Installer.Roles.Role | Where-Object { $_.Server -eq $SQLCluster } | Sort-Object { $_.Instance } -Unique | ForEach-Object { $_.Instance }
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "SQL cluster $SQLCluster instance is $Instance" -Status $true
								# Get features and collation for SQL instance
								$SQLFeatures = ""
								$SQLCollation = ""
								$Variable.Installer.Roles.Role | Where-Object { ($_.Server -eq $SQLCluster) -and ($_.Instance -eq $Instance) } | ForEach-Object {
									$Role = $_.Name
									$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.SQL } | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Feature } | Where-Object { $_ -ne $Null } | ForEach-Object {
										New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance needs $_ for $Role"
										If ($SQLFeatures -eq "") { $SQLFeatures = $_ }
										If (!($SQLFeatures.Contains($_))) { $SQLFeatures = $SQLFeatures + "," + $_ }
										$SQLCollation = $Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.SQL } | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Collation }
									}
									Switch ($SQLCollation)
									{
										"Default" { $SQLCollation = "SQL_Latin1_General_CP1_CI_AS" }
										"Locale" {
											Switch ($Locale)
											{
												"0409" { $SQLCollation = "Latin1_General_100_CI_AS" }
												"0804" { $SQLCollation = "Chinese_Simplified_Pinyin_100_CI_AS" }
												"0404" { $SQLCollation = "Chinese_Traditional_Stroke_Count_100_CI_AS" }
												"0405" { $SQLCollation = "Czech_100_CI_AS" }
												"0406" { $SQLCollation = "Danish_Norwegian_CI_AS" }
												"0413" { $SQLCollation = "Latin1_General_100_CI_AS" }
												"040B" { $SQLCollation = "Finnish_Swedish_100_CI_AS" }
												"040C" { $SQLCollation = "French_100_CI_AS" }
												"0407" { $SQLCollation = "Latin1_General_100_CI_AS" }
												"0408" { $SQLCollation = "Greek_100_CI_AS" }
												"0410" { $SQLCollation = "Latin1_General_100_CI_AS" }
												"0411" { $SQLCollation = "Japanese_XJIS_100_CI_AS" }
												"0412" { $SQLCollation = "Korean_100_CI_AS" }
												"0414" { $SQLCollation = "Norwegian_100_CI_AS" }
												"0415" { $SQLCollation = "Polish_100_CI_AS" }
												"0816" { $SQLCollation = "Latin1_100_CI_AS" }
												"0416" { $SQLCollation = "Latin1_General_100_CI_AS" }
												"0419" { $SQLCollation = "Cyrillic_General_100_CI_AS" }
												"0C0A" { $SQLCollation = "Modern_Spanish_100_CI_AS" }
												"041D" { $SQLCollation = "Finnish_Swedish_100_CI_AS" }
												"041F" { $SQLCollation = "Turkish_100_CI_AS" }
												Default { $SQLCollation = "Latin1_General_100_CI_AS" }
											}
										}
										Default { $SQLCollation = "SQL_Latin1_General_CP1_CI_AS" }
									}
								}
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance features are $SQLFeatures" -Status $true
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance collation is $SQLCollation"
								# If cluster group exists, move to the first node so validation passes
								If ($SQLClusterNodes[0] -eq $Server)
								{
									If (!(Get-Module FailoverClusters))
									{
										New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Importing failover clustering Powershell module"
										If (!(Get-WindowsFeature RSAT-Clustering-Powershell | Where-Object { $_.Installed }))
										{
											Add-WindowsFeature RSAT-Clustering-Powershell
										}
										Import-Module FailoverClusters
									}
									$ClusterOwner = (Get-ClusterGroup -Name $SQLClusterShort -Cluster $SQLClusterShort -ErrorAction SilentlyContinue).OwnerNode.Name
									If (($ClusterOwner -ne $null) -and ($ClusterOwner -ne $Server.split(".")[0]))
									{
										New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Moving SQL cluster $SQLClusterShort to $Server"
										Move-ClusterGroup -Name $SQLClusterShort -Cluster $SQLClusterShort -Node $Server
									}
								}
								# Get SQL cluster node install
								$Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $SQLVersion } | ForEach-Object {
									$SourceName = $_.Name
									Invoke-Expression ("`$SourceFolder = `"" + $_.SourceFolder + "`"")
									$Install = $_.Install | Where-Object { $_.Name -eq "$SQLVersion Cluster Prepare" }
									$InstallName = $Install.Name
								}
								# Get instance validation
								$Install.Validation | ForEach-Object {
									$Condition = $false
									If ($_.Condition -ne $null)
									{
										Invoke-Expression ("If (" + $_.Condition + ") {`$Condition = `$true}")
									}
									Else { $Condition = $true }
									If ($Condition)
									{
										Invoke-Expression ("`$Type = " + "`"" + $_.Type + "`"")
										Invoke-Expression ("`$Value = " + "`"" + $_.Value + "`"")
									}
								}
								# Get SQL variables
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading SQL version variables from workflow.xml"
								$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading SQL version variables from variable.xml"
								$Variable.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading SQL server variables from variable.xml"
								$Variable.Installer.SQL.Server | Where-Object { $_.Server -eq $Server } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading SQL cluster variables from variable.xml"
								$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLCluster } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading SQL cluster node variables from variable.xml"
								$Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLCluster } | ForEach-Object { $_.Node } | Where-Object { $_.Server -eq $Server } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
									Set-ScriptVariable -Name $_.Name -Value $_.Value
								}
								If (!(Validate -Server $Server -Type $Type -Value $Value))
								{
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance is not installed"
									# Copy source
									Copy-Source -SourceName $SourceName -Source "$SourcePath\$SourceFolder" -Destination "\\$Server\$TempPathUNC\Installer\$SourceFolder"
									# Install cluster node
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Installing $SQLVersion cluster $SQLCluster instance $Instance " -Status $true
									Invoke-Install -Server $Server -Install $Install
									# Validate installation
									If (!(Validate -Server $Server -Type $Type -Value $Value))
									{
										New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed installing $SQLVersion instance $Instance " -Status $true
										Fail -Server $Server
										$Global:Success | Out-File "$LogFolder\Temp\$SQLCluster.$Server.sql"
									}
									Else
									{
										New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance is installed" -Status $true
										If ($SQLClusterNodes[0] -ne $Server)
										{
											$Global:Success | Out-File "$LogFolder\Temp\$SQLCluster.$Server.sql"
										}
									}
								}
								Else
								{
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance is installed" -Status $true
									If ($SQLClusterNodes[0] -ne $Server)
									{
										$Global:Success | Out-File "$LogFolder\Temp\$SQLCluster.$Server.sql"
									}
								}
								# Wait for cluster nodes
								If ($Global:Success)
								{
									$SQLClusterNodes | ForEach-Object {
										If ($Global:Success)
										{
											If (($SQLClusterNodes[0] -ne $Server) -or (($SQLClusterNodes[0] -eq $Server) -and ($_ -ne $Server)))
											{
												"Yellow" | Out-File $ColorFile
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Waiting for SQL cluster $SQLCluster node $_" -Status $true
												While (!(Test-Path("$LogFolder\Temp\$SQLCluster.$_.sql")))
												{
													Start-Sleep 1
												}
												"White" | Out-File $ColorFile
												If ((Get-Content "$LogFolder\Temp\$SQLCluster.$_.sql") -eq "False")
												{
													New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed dependency SQL cluster $SQLCluster node $_" -Status $true
													Fail -Server $Server
												}
											}
										}
									}
								}
								If ($Global:Success)
								{
									If ($SQLClusterNodes[0] -eq $Server)
									{
										# Get SQL cluster node completion
										$Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $SQLVersion } | ForEach-Object {
											$SourceName = $_.Name
											Invoke-Expression ("`$SourceFolder = `"" + $_.SourceFolder + "`"")
											$Install = $_.Install | Where-Object { $_.Name -eq "$SQLVersion Cluster Complete" }
											$InstallName = $Install.Name
										}
										# Get SQL cluster node completion validation
										$Install.Validation | ForEach-Object {
											$Condition = $false
											If ($_.Condition -ne $null)
											{
												Invoke-Expression ("If (" + $_.Condition + ") {`$Condition = `$true}")
											}
											Else { $Condition = $true }
											If ($Condition)
											{
												Invoke-Expression ("`$Type = " + "`"" + $_.Type + "`"")
												Invoke-Expression ("`$Value = " + "`"" + $_.Value + "`"")
											}
										}
										If (!(Validate -Server $Server -Type $Type -Value $Value))
										{
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance is not completed"
											# Complete cluster node
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Completing $SQLVersion cluster $SQLCluster instance $Instance " -Status $true
											Invoke-Install -Server $Server -Install $Install
											# Validate completion
											If (!(Validate -Server $Server -Type $Type -Value $Value))
											{
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed completing $SQLVersion instance $Instance " -Status $true
												Fail -Server $Server
												$Global:Success | Out-File "$LogFolder\Temp\$SQLCluster.$Server.sql"
											}
											Else
											{
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance is completed" -Status $true
												$Global:Success | Out-File "$LogFolder\Temp\$SQLCluster.$Server.sql"
											}
										}
										Else
										{
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance is completed" -Status $true
											$Global:Success | Out-File "$LogFolder\Temp\$SQLCluster.$Server.sql"
										}
									}
								}
								# Set preferred node and move resource group
								If ($Global:Success)
								{
									If ($SQLClusterNodes[0] -eq $Server)
									{
										$PreferredNodes = @($Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLCluster } | ForEach-Object { $_.Node } | Where-Object { $_.Preferred -ne $null } | Sort-Object { $_.Preferred } | ForEach-Object { $_.Server.Split(".")[0] })
										If ($PreferredNodes -ne $null)
										{
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "SQL cluster $SQLCluster preferred nodes: $PreferredNodes"
											If (!(Get-Module FailoverClusters))
											{
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Importing failover clustering Powershell module"
												If (!(Get-WindowsFeature RSAT-Clustering-Powershell | Where-Object { $_.Installed }))
												{
													Add-WindowsFeature RSAT-Clustering-Powershell
												}
												Import-Module FailoverClusters
											}
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Setting preferred nodes for SQL cluster $SQLClusterShort to $PreferredNodes"
											Set-ClusterOwnerNode -Owners $PreferredNodes -Group "$SQLClusterShort" -Cluster $SQLClusterShort
											$PreferredNode = $PreferredNodes[0]
											If ((Get-ClusterGroup -Name $SQLClusterShort -Cluster $SQLClusterShort).OwnerNode.Name -ne $PreferredNode)
											{
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Moving SQL cluster $SQLClusterShort to $PreferredNode"
												Move-ClusterGroup -Name $SQLClusterShort -Cluster $SQLClusterShort -Node $PreferredNode
											}
										}
									}
								}
							}
						}
					}
				}
				If ($Global:Success) { New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "End SQL clusters" -Status $true }
			}
			$SQLCluster = $null
		}
		Else
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Skipping installer stage 3 - SQLClusters"
		}
		#endregion SQL clusters
		
		#region SQL
		If ($InstallerStage -ge 4)
		{
			If ($Global:Success)
			{
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Start SQL" -Status $true
				# Get unique SQL instances for this server
				$Instances = $Variable.Installer.Roles.Role | Where-Object { ($_.Server -eq $Server) -and ($_.Existing -ne "True") -and ($_.SQLCluster -ne "True") } | Sort-Object { $_.Instance } -Unique | ForEach-Object { $_.Instance }
				$Instances | Where-Object { $_ -ne $Null } | ForEach-Object {
					If ($Global:Success)
					{
						$Instance = $_
						$SQLVersion = $Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object { $_.Version }
						$SQLPort = $Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object { $_.Port }
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "SQL instance $Instance version is $SQLVersion" -Status $true
						# Get features and collation for SQL instance
						$SQLFeatures = ""
						$SQLCollation = ""
						$Variable.Installer.Roles.Role | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object {
							$Role = $_.Name
							$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.SQL } | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Feature } | Where-Object { $_ -ne $Null } | ForEach-Object {
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance needs $_ for $Role"
								If ($SQLFeatures -eq "") { $SQLFeatures = $_ }
								If (!($SQLFeatures.Contains($_))) { $SQLFeatures = $SQLFeatures + "," + $_ }
								$SQLCollation = $Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.SQL } | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Collation }
							}
							Switch ($SQLCollation)
							{
								"Default" { $SQLCollation = "SQL_Latin1_General_CP1_CI_AS" }
								"Locale" {
									Switch ($Locale)
									{
										"0409" { $SQLCollation = "Latin1_General_100_CI_AS" }
										"0804" { $SQLCollation = "Chinese_Simplified_Pinyin_100_CI_AS" }
										"0404" { $SQLCollation = "Chinese_Traditional_Stroke_Count_100_CI_AS" }
										"0405" { $SQLCollation = "Czech_100_CI_AS" }
										"0406" { $SQLCollation = "Danish_Norwegian_CI_AS" }
										"0413" { $SQLCollation = "Latin1_General_100_CI_AS" }
										"040B" { $SQLCollation = "Finnish_Swedish_100_CI_AS" }
										"040C" { $SQLCollation = "French_100_CI_AS" }
										"0407" { $SQLCollation = "Latin1_General_100_CI_AS" }
										"0408" { $SQLCollation = "Greek_100_CI_AS" }
										"0410" { $SQLCollation = "Latin1_General_100_CI_AS" }
										"0411" { $SQLCollation = "Japanese_XJIS_100_CI_AS" }
										"0412" { $SQLCollation = "Korean_100_CI_AS" }
										"0414" { $SQLCollation = "Norwegian_100_CI_AS" }
										"0415" { $SQLCollation = "Polish_100_CI_AS" }
										"0816" { $SQLCollation = "Latin1_100_CI_AS" }
										"0416" { $SQLCollation = "Latin1_General_100_CI_AS" }
										"0419" { $SQLCollation = "Cyrillic_General_100_CI_AS" }
										"0C0A" { $SQLCollation = "Modern_Spanish_100_CI_AS" }
										"041D" { $SQLCollation = "Finnish_Swedish_100_CI_AS" }
										"041F" { $SQLCollation = "Turkish_100_CI_AS" }
										Default { $SQLCollation = "Latin1_General_100_CI_AS" }
									}
								}
								Default { $SQLCollation = "SQL_Latin1_General_CP1_CI_AS" }
							}
						}
					}
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance features are $SQLFeatures" -Status $true
					New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance collation is $SQLCollation"
					# Get SQL install
					$Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $SQLVersion } | ForEach-Object {
						$SourceName = $_.Name
						Invoke-Expression ("`$SourceFolder = `"" + $_.SourceFolder + "`"")
						$Install = $_.Install | Where-Object { $_.Name -eq $SQLVersion }
						$InstallName = $Install.Name
					}
					# Get instance validation
					$Install.Validation | ForEach-Object {
						$Condition = $false
						If ($_.Condition -ne $null)
						{
							Invoke-Expression ("If (" + $_.Condition + ") {`$Condition = `$true}")
						}
						Else { $Condition = $true }
						If ($Condition)
						{
							Invoke-Expression ("`$Type = " + "`"" + $_.Type + "`"")
							Invoke-Expression ("`$Value = " + "`"" + $_.Value + "`"")
						}
					}
					# If instance is not installed...
					If (!(Validate -Server $Server -Type $Type -Value $Value))
					{
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance is not installed"
						# Get SQL variables
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading SQL version variables from workflow.xml"
						$Workflow.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading SQL version variables from variable.xml"
						$Variable.Installer.SQL.SQL | Where-Object { $_.Version -eq $SQLVersion } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading SQL server variables from variable.xml"
						$Variable.Installer.SQL.Server | Where-Object { $_.Server -eq $Server } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading SQL instance variables from variable.xml"
						$Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
							Set-ScriptVariable -Name $_.Name -Value $_.Value
						}
						# Install it
						Copy-Source -SourceName $SourceName -Source "$SourcePath\$SourceFolder" -Destination "\\$Server\$TempPathUNC\Installer\$SourceFolder"
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Installing $SQLVersion instance $Instance " -Status $true
						Invoke-Install -Server $Server -Install $Install
						# Validate installation
						If (!(Validate -Server $Server -Type $Type -Value $Value))
						{
							New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed installing $SQLVersion instance $Instance " -Status $true
							Fail -Server $Server
						}
						Else
						{
							New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance is installed" -Status $true
							# Enable AlwaysOn
							If ($Variable.Installer.Roles.Role | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) -and ($_.SQLAlwaysOn -eq "True") })
							{
								$Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $SQLVersion } | ForEach-Object {
									$SourceName = $_.Name
									Invoke-Expression ("`$SourceFolder = `"" + $_.SourceFolder + "`"")
									$Install = $_.Install | Where-Object { $_.Name -eq "$SQLVersion AlwaysOn" }
									$InstallName = $Install.Name
								}
								Invoke-Install -Server $Server -Install $Install
							}
						}
					}
					Else
					{
						New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$SQLVersion instance $Instance is installed" -Status $true
						
					}
				}
				If ($Global:Success) { New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "End SQL" -Status $true }
			}
		}
		Else
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Skipping installer stage 4 - SQL"
		}
		#endregion SQL
		
		#region Prerequisites
		If ($InstallerStage -ge 5)
		{
			If ($Global:Success)
			{
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Start prerequisites" -Status $true
				# For each install...
				$Workflow.Installer.Installables.Installable | ForEach-Object {
					$SourceName = $_.Name
					Invoke-Expression ("`$SourceFolder = `"" + $_.SourceFolder + "`"")
					$_.Install | Where-Object { $_ -ne $null } | ForEach-Object {
						If ($Global:Success)
						{
							$Install = $_
							$InstallName = $_.Name
							$InstallRequired = $false
							# ...check if any role requires it
							$Roles | ForEach-Object {
								If ($Global:Success)
								{
									$Role = $_
									$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object { $_.Prerequisites } | Where-Object { $_.OSVersion -eq $OSVersion } | ForEach-Object { $_.Prerequisite } | Where-Object { $_.Name -eq $InstallName } | ForEach-Object {
										$Condition = $False
										If ($_.Condition -ne $null)
										{
											Invoke-Expression ("If (" + $_.Condition + ") {`$Condition = `$True}")
										}
										Else
										{
											$Condition = $True
										}
										If ($Condition)
										{
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Prerequisite $InstallName is required for $Role"
											$InstallRequired = $true
										}
									}
								}
							}
							# If it's required, check to see if it's installed
							If ($InstallRequired)
							{
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Prerequisite $InstallName is required" -Status $true
								# If it's not installed...
								Invoke-Expression ("`$Type = " + "`"" + $Install.Validation.Type + "`"")
								Invoke-Expression ("`$Value = " + "`"" + $Install.Validation.Value + "`"")
								If (!(Validate -Server $Server -Type $Type -Value $Value))
								{
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Prerequisite $InstallName is not installed" -Status $true
									# Install it!
									If ($SourceFolder -ne "")
									{
										Copy-Source -SourceName $SourceName -Source "$SourcePath\$SourceFolder" -Destination "\\$Server\$TempPathUNC\Installer\$SourceFolder"
									}
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Installing $InstallName" -Status $true
									Invoke-Install -Server $Server -Install $Install
									If ($Global:Success)
									{
										# Validate installation
										If (($Install.Validation.Type -ne "None") -and (!(Validate -Server $Server -Type $Type -Value $Value)))
										{
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed installing prerequisite $InstallName" -Status $true
											Fail -Server $Server
										}
										Else
										{
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Prerequisite $InstallName is installed" -Status $true
										}
									}
								}
								Else
								{
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Prerequisite $InstallName is installed" -Status $true
								}
							}
						}
					}
				}
				If ($Global:Success) { New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "End prerequisites" -Status $true }
			}
		}
		Else
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Skipping installer stage 5 - Prereqs"
		}
		#endregion Prerequisites
		
		#region Roles
		If ($InstallerStage -ge 6)
		{
			If ($Global:Success)
			{
				New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Start roles" -Status $true
				$Workflow.Installer.Roles.Role | ForEach-Object {
					$Role = $_
					$Roles | ForEach-Object {
						$ThisRole = $_
						If ($Global:Success)
						{
							If ($_ -eq $Role.Name)
							{
								New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$ThisRole is needed" -Status $true
								$Condition = $False
								If ($Role.Condition -ne $null)
								{
									Invoke-Expression ("If (" + $Role.Condition + ") {`$Condition = `$True}")
								}
								Else
								{
									$Condition = $True
								}
								If ($Condition)
								{
									$Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $Role.Install.Installable } | ForEach-Object {
										$SourceName = $_.Name
										Invoke-Expression ("`$SourceFolder = `"" + $_.SourceFolder + "`"")
										$_.Install | Where-Object { $_.Name -eq $Role.Install.Install } | ForEach-Object {
											$Install = $_
											$InstallName = $_.Name
											Invoke-Expression ("`$SourceSubFolder = `"" + $_.SourceSubFolder + "`"")
											Invoke-Expression ("`$Type = " + "`"" + $_.Validation.Type + "`"")
											Invoke-Expression ("`$Value = " + "`"" + $_.Validation.Value + "`"")
											If (($_.Validation -eq $null) -or (!(Validate -Server $Server -Type $Type -Value $Value)))
											{
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$ThisRole is not installed" -Status $true
												If ($SourceFolder -ne "")
												{
													If ($SourceSubFolder -ne "None")
													{
														Copy-Source -SourceName $SourceName -Source "$SourcePath\$SourceFolder\$SourceSubFolder" -Destination "\\$Server\$TempPathUNC\Installer\$SourceFolder\$SourceSubFolder"
													}
												}
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading role variables from workflow.xml"
												$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role.Name } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
													Set-ScriptVariable -Name $_.Name -Value $_.Value
												}
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Reading role variables from variable.xml"
												$Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $Role.Name) -and ($_.Server -eq $Server) } | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object {
													Set-ScriptVariable -Name $_.Name -Value $_.Value
												}
												# Check for dependencies
												$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role.Name } | ForEach-Object { $_.Dependency } | Where-Object { $_.Name -ne $Null } | ForEach-Object {
													If ($Global:Success)
													{
														$Dependency = $_.Name
														"Yellow" | Out-File $ColorFile
														New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Waiting for $Dependency" -Status $true
														$DependencyFile = $_.Name.Replace(" ", "")
														If (!(Test-Path("$LogFolder\Temp\$DependencyFile.role")))
														{
															If (($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Dependency }).Type -eq "Integration")
															{
																$DependencyServer = ($Workflow.Installer.Integrations.Integration | Where-Object { $_.Name -eq $Dependency } | Sort-Object { $_.Name } -Unique | ForEach-Object { $_.Target }).Replace(" ", "")
																$DependencyServer = Invoke-Expression ("`$$DependencyServer")
															}
															Else
															{
																$DependencyServer = Invoke-Expression ("`$$DependencyFile")
															}
															New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Waiting for $Dependency on $DependencyServer" -Status $true
															$DependencyFile = $DependencyFile + "." + $DependencyServer
															While (!(Test-Path("$LogFolder\Temp\$DependencyFile.role")))
															{
																Start-Sleep 1
															}
															"White" | Out-File $ColorFile
															If ((Get-Content "$LogFolder\Temp\$DependencyFile.role") -eq "False")
															{
																New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed dependency $Dependency" -Status $true
																Fail -Server $Server
															}
														}
														Else
														{
															New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Missing dependency $Dependency" -Status $true
															Fail -Server $Server
														}
													}
												}
												# Check for sequential installs
												If ($Role.Multiple -eq "Sequential")
												{
													$SequentialInstalled = $false
													If ($Global:Success)
													{
														$Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role.Name } | Sort-Object { $_.Server } -Unique | ForEach-Object {
															If (!($SequentialInstalled) -and ($_.Server -ne $Server))
															{
																$SequentialDependency = $_.Server
																"Yellow" | Out-File $ColorFile
																New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Waiting for $SequentialDependency" -Status $true
																$DependencyFile = $Role.Name.Replace(" ", "")
																While (!(Test-Path("$LogFolder\Temp\$DependencyFile.$SequentialDependency.role")))
																{
																	Start-Sleep 1
																}
																"White" | Out-File $ColorFile
															}
															Else
															{
																$SequentialInstalled = $true
															}
														}
													}
												}
												# Install
												If ($Global:Success)
												{
													New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Installing $InstallName" -Status $true
													Invoke-Install -Server $Server -Install $Install
													If (($Install.Validation.Type -ne "None") -and (!(Validate -Server $Server -Type $Type -Value $Value)))
													{
														New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Failed to install $ThisRole" -Status $true
														Fail -Server $Server
													}
													Else
													{
														New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$ThisRole is installed" -Status $true
														$ThisRole = $ThisRole.Replace(" ", "")
														$Global:Success | Out-File "$LogFolder\Temp\$ThisRole.$Server.role"
													}
												}
											}
											Else
											{
												New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$ThisRole is installed" -Status $true
												$Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $ThisRole) -and ($_.SQLCluster -eq "True") } | Where-Object { $_ -ne $null } | ForEach-Object {
													$ThisRole = $ThisRole.Replace(" ", "")
													$Cluster = $_.Server
													$Global:Success | Out-File "$LogFolder\Temp\$ThisRole.$Cluster.role"
												}
												$ThisRole = $ThisRole.Replace(" ", "")
												$Global:Success | Out-File "$LogFolder\Temp\$ThisRole.$Server.role"
											}
										}
									}
									If (!($Workflow.Installer.Installables.Installable | Where-Object { $_.Name -eq $Role.Install.Installable }))
									{
										If ($Global:Success)
										{
											New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$ThisRole is installed" -Status $true
											$Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $ThisRole) -and ($_.SQLCluster -eq "True") } | Where-Object { $_ -ne $null } | ForEach-Object {
												$ThisRole = $ThisRole.Replace(" ", "")
												$Cluster = $_.Server
												$Global:Success | Out-File "$LogFolder\Temp\$ThisRole.$Cluster.role"
											}
											$ThisRole = $ThisRole.Replace(" ", "")
											$Global:Success | Out-File "$LogFolder\Temp\$ThisRole.$Server.role"
										}
									}
								}
								Else
								{
									New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "$ThisRole is installed" -Status $true
									$Variable.Installer.Roles.Role | Where-Object { ($_.Name -eq $ThisRole) -and ($_.SQLCluster -eq "True") } | Where-Object { $_ -ne $null } | ForEach-Object {
										$ThisRole = $ThisRole.Replace(" ", "")
										$Cluster = $_.Server
										$Global:Success | Out-File "$LogFolder\Temp\$ThisRole.$Cluster.role"
									}
									$ThisRole = $ThisRole.Replace(" ", "")
									$Global:Success | Out-File "$LogFolder\Temp\$ThisRole.$Server.role"
								}
							}
						}
					}
				}
				If ($Global:Success) { New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "End roles" -Status $true }
			}
		}
		Else
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Skipping installer stage 6 - Roles"
		}
		#endregion Roles
		
		#region Log files
		# Copy log files
		If (Test-Path "\\$Server\$TempPathUNC\Installer\$Deployment")
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Copying log files" -Status $true
			Start-Process -FilePath "robocopy.exe" -ArgumentList "\\$Server\$TempPathUNC\Installer\$Deployment `"$TempPath\$Deployment\$Server`" /e" -Wait -WindowStyle Hidden
		}
		If ($Global:Success)
		{
			New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "Cleaning up" -Status $true
			Remove-Item -Path "\\$Server\$TempPathUNC\Installer" -Recurse -Force
			"Green" | Out-File $ColorFile
		}
		New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server $Server -Message "End $Server" -Status $true
		Start-Sleep 5
		#endregion Log files
		
	} -ArgumentList @($Deployment, $Server, $LogFolder, $LogFile, $Path, $Mode, $InstallerStage)
}
#endregion Per Server

#region Progress Display
# Progress display
Clear-Host
If (!(Test-Path "$TempPath\$Deployment")) { New-Item "$TempPath\$Deployment" -ItemType Directory | Out-Null }
$UICursor = $Host.UI.RawUI.CursorPosition
$Components = $Workflow.Installer.Components.Component | ForEach-Object { $_.Name }
$ServerJobs | ForEach-Object {
	While ((Get-Job -Id $_.Id).State -eq "Running")
	{
		If (Test-Path "$TempPath\$Deployment\Status.txt") { Remove-Item "$TempPath\$Deployment\Status.txt" }
		$Host.UI.RawUI.CursorPosition = $UICursor
		$UIHeight = $Host.UI.RawUI.WindowSize.Height - 2
		$UIWidth = $Host.UI.RawUI.WindowSize.Width
		$UILineCount = 0
		$Components | ForEach-Object {
			$Component = $_
			$CR = $False
			$Workflow.Installer.Roles.Role | Where-Object { $_.Component -eq $Component } | ForEach-Object {
				$Role = $_.Name
				$Variable.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object {
					If ($CR -eq $False)
					{
						If ($UILineCount -le $UIHeight) { Write-Host $Component -ForegroundColor "White"; $UILineCount++ }
						Add-Content -Path "$TempPath\$Deployment\Status.txt" -Value $Component -Encoding Ascii
						$CR = $True
					}
					$Server = $_.Server
					If ($_.SQLCluster -ne $null)
					{
						$Server = @($Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $Server } | ForEach-Object { $_.Node.Server })
					}
					$Server | ForEach-Object {
						$StatusFile = "$LogFolder\Temp\" + $_ + ".status"
						$ColorFile = "$LogFolder\Temp\" + $_ + ".color"
						If (Test-Path $StatusFile)
						{
							$Status = Get-Content ($StatusFile)
							$StatusTime = (((Get-Date) - (Get-ChildItem $StatusFile).LastWriteTime).ToString()).SubString(0, 8)
						}
						Else
						{
							$Status = ""
							$StatusTime = ""
						}
						If (Test-Path $ColorFile) { $Foreground = Get-Content ($ColorFile) }
						If ($Foreground -eq $Null) { $Foreground = "Yellow" }
						$Display = $Role.Replace($Component, "") + ": " + $_ + ": " + $Status + ": " + $StatusTime
						Add-Content -Path "$TempPath\$Deployment\Status.txt" -Value $Display -Encoding Ascii
						If ($Display.Length -ge $UIWidth)
						{
							$Display = $Display.Substring(0, $UIWidth - 1)
						}
						ElseIf ($Display.Length -lt $UIWidth)
						{
							$Pad = " " * ($UIWidth - $Display.Length - 1)
							$Display = $Display + $Pad
						}
						If ($UILineCount -le $UIHeight) { Write-Host $Display -ForegroundColor $Foreground; $UILineCount++ }
					}
				}
			}
			If ($cr -eq $True)
			{
				If ($UILineCount -le $UIHeight)
				{
					Write-Host (" " * ($UIWidth - 1))
					Add-Content -Path "$TempPath\$Deployment\Status.txt" -Value "" -Encoding Ascii
					$UILineCount++
				}
			}
		}
		$TotalTime = (((Get-Date) - $StartTime).ToString()).Substring(0, 8)
		If ($UILineCount -le $UIHeight) { Write-Host "Total time: $TotalTime"; $UILineCount++ }
		Add-Content -Path "$TempPath\$Deployment\Status.txt" -Value "Total time: $TotalTime" -Encoding Ascii
		If ($UILineCount -le $UIHeight) { Write-Host ""; $UILineCount++ }
		While ($UILineCount -le $UIHeight) { Write-Host (" " * ($UIWidth - 1)); $UILineCount++ }
		Start-Sleep 1
	}
}

If (Test-Path "$env:SystemDrive\Temp\ShellSetup.ps1") { &"$env:SystemDrive\Temp\ShellSetup.ps1" }
If (Test-Path "$env:SystemDrive\Users\Default\Desktop\ShellSetup.ps1") { &"$env:SystemDrive\Users\Default\Desktop\ShellSetup.ps1" }

# Stop the central logger job after allowing it to pick up final log entries
While (Get-Item "$LogFolder\Log\*.log" -ErrorAction SilentlyContinue) { Start-Sleep 1 }
New-LogEntry -Deployment $Deployment -LogFolder $LogFolder -LogFile $LogFile -Server "Controller" -Message "End"
Start-Sleep 1
Stop-Job -Job $LogJob
#endregion Progress Display

#region Post Installer
$Success = $true
If (Get-ChildItem -Path "$env:LocalAppData\Installer\*.log" -ErrorAction SilentlyContinue)
{
	Get-ChildItem -Path "$env:LocalAppData\Installer\*.log" | Where-Object { $_.Name -ne 'Installer.log' } | ForEach-Object {
		If ((Get-Content -Path $_ -Tail 2)[0].substring(0, 11) -ne 'Cleaning up') { $Success = $false }
	}
}
Else
{
	$Success = $false
}

If ($Success)
{
	If (Test-Path 'C:\Temp\PostInstaller.ps1')
	{
		& C:\Temp\PostInstaller.ps1}
	}
	#endregion Post Installer