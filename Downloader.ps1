<# 	
  .NOTES
	Copyright 2014 (c) Microsoft Corporation.  All rights reserved.
		
	A WSSC CAT Solution Created by Rob Willis
	
	In collaboration with:
		PowerShell Deployment Toolkit Team (PDT)
		America Enterprise Services - Azure IaaS Center of Expertise (COE)
		Service Provider Operational Readiness Kit (ORK)
		Datacenter and Cloud Infrastrucutre Services (COE)
               	
	File:		Downloader.ps1
	
	Pre-Reqs:	Windows Server 2012 or Windows Server 2012 R2, and Windows PowerShell 4.0	
				
	Version: 	2.65.5.0

	Contributors:    Rob Willis, Robert Larson, Joel Stidley, David McFarlane-Smith, Joze Markic


 .SYNOPSIS
    Downloader is part of the PowerShell Deployment Toolkit and is used to download all of the prerequisite installation media.
  
 .DESCRIPTION
	This script is used to download the required content for use with the PDT deployment process. 
  
	 		
 .EXAMPLE
	C:\PS> .\Downloader.ps1 -Path C:\PDT
	
	Description
	-----------
	This command uses the Variable.xml and Workflow.xml files in the C:\PDT directory to define what is downloaded and where the files will be stored.
	All files will be downloaded, even those not required for the deployment defined in variable.xml.
	
 .EXAMPLE
	C:\PS> .\Downloader.ps1 -DeploymentOnly
	
	Description
	-----------
	This command uses the Variable.xml and Workflow.xml files in the local directory to define what is downloaded and where the files will be stored.
	
	Only the files required to complete the deployment defined in the Variable.xml file will be downloaded.
	
 .EXAMPLE
	C:\PS> .\Downloader.ps1 -DeploymentOnly -GetLatest
	
	Description
	-----------
	This command uses the Variable.xml and Workflow.xml files in the local directory to define what is downloaded and where the files will be stored.
	
	All files required to complete the deployment defined in the Variable.xml file will be redownloaded.
	
 .PARAMETER Path
	Specifies the path to the Variable.xml, Workflow.xml, Installer.ps1, and any Extender files that will be used.

 .PARAMETER DeploymentOnly
	Specifies whether to only download the installation files required for the deployment defined in Variable.xml.
	
 .PARAMETER GetLatest
	Specifies whether to redownload files that have already been downloaded to ensure the latest version has been downloaded.

 .INPUTS
           None.

 .OUTPUTS
           None.

 .LINK
	http://aka.ms/pdt
#>

PARAM
(
	[Parameter(Mandatory = $false, Position = 0)]
	[String]$Path = (Get-Location),
	
	[Parameter(Mandatory = $false)]
	[Switch]$DeploymentOnly = $false,
	
	[Parameter(Mandatory = $false)]
	[Switch]$GetLatest = $false
)

$host.UI.RawUI.BackgroundColor = "Black"; Clear-Host

# Elevate
Write-Host " Checking for elevation... " -NoNewline
$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
if (($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) -eq $false)
{
	$ArgumentList = "-noprofile -noexit -file `"{0}`" -Path `"$Path`""
	If ($DeploymentOnly) { $ArgumentList = $ArgumentList + " -DeploymentOnly" }
	Write-Host "elevating"
	Start-Process powershell.exe -Verb RunAs -ArgumentList ($ArgumentList -f ($myinvocation.MyCommand.Definition))
	Exit
}

$Host.UI.RawUI.BackgroundColor = "Black"; Clear-Host
$StartTime = Get-Date
$Validate = $true

# Check PS host
If ($Host.Name -ne 'ConsoleHost')
{
	$Validate = $false
	Write-Host " Downloader.ps1 should not be run from ISE" -ForegroundColor Red
}

# Change to path
If (Test-Path $Path -PathType Container)
{
	Set-Location $Path
}
Else
{
	$Validate = $false
	Write-Host " Invalid path" -ForegroundColor Red
}

Write-Host 
Write-Host " Start time:" (Get-Date)
Write-Host `n`n`n`n`n`n`n`n

# Check for WebPI and RAR/7Z/PeaZip
Write-Host " Verifying extraction software... " -NoNewLine
$WR = (Get-ItemProperty -Path "HKLM:\SOFTWARE\WinRAR" -ErrorAction SilentlyContinue).Exe64
If (($WR -ne $null) -and (Test-Path "$WR"))
{
	$Extractor = "WinRAR"
	$ExtractorExe = "$WR"
}
$7z = (Get-ItemProperty -Path "HKLM:\SOFTWARE\7-Zip" -ErrorAction SilentlyContinue).Path
If ($7z -ne $null)
{
	if (!($7z.EndsWith("\"))) { $7z = $7z + "\" }
	if (Test-Path "$7z`7z.exe")
	{
		$Extractor = "7-Zip"
		$ExtractorExe = "$7z`7z.exe"
	}
}
$PZ = (Get-ItemProperty -Path "HKLM:\SOFTWARE\PeaZip" -ErrorAction SilentlyContinue)
If ($PZ -ne $null)
{
	$PZLoc = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{5A2BC38A-406C-4A5B-BF45-6991F9A05325}_is1" -ErrorAction SilentlyContinue).InstallLocation
	if (Test-Path "$PZLoc`peazip.exe")
	{
		$Extractor = "7-Zip"
		$ExtractorExe = "$PZLoc" + "res\7z\7z.exe"
	}
}

If (!($Extractor))
{
	Write-Host "Warning" -ForegroundColor Yellow
	Write-Host "   7-Zip, PeaZip, or WinRAR not found. Please install one of these tools to enable Downloader to extract files." -ForegroundColor Yellow
}Else
{
	Write-Host "Passed" -ForegroundColor Green
}
Write-Host
Write-Host " Verifying WebPI... " -NoNewLine
$WPI = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WebPlatformInstaller\5" -ErrorAction SilentlyContinue).InstallPath
If (($WPI -eq $null) -or !(Test-Path "$WPI\WebpiCmd.exe"))
{
	Write-Host "Warning" -ForegroundColor Yellow
	Write-Host "   Web Platform Installer 5 (WebPI) not found. Please install WebPI 5 to enable Downloader to retrieve all required files." -ForegroundColor Yellow
}
Else
{
	Write-Host "Passed" -ForegroundColor Green
}

# Read input files
If (Test-Path "$Path\Workflow.xml")
{
	try { $Workflow = [XML] (Get-Content "$Path\Workflow.xml") }
	catch { $Validate = $false; Write-Host " Invalid Workflow.xml" -ForegroundColor Red }
}
Else
{
	$Validate = $false
	Write-Host " Missing Workflow.xml" -ForegroundColor Red
}
If (Test-Path "$Path\Extender*.xml")
{
	Get-ChildItem -Path "$Path\Extender*.xml" | ForEach-Object {
		$ExtenderFile = $_.Name
		try { $Extender = [XML] (Get-Content "$Path\$ExtenderFile") }
		catch { $Validate = $false; Write-Host " Invalid Extender.xml" -ForegroundColor Red }
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
If ($DeploymentOnly)
{

	If (Test-Path "$Path\Variable.xml")
	{
		try { $Variable = [XML] (Get-Content "$Path\Variable.xml") }
		catch { $Validate = $false; Write-Host " Invalid Variable.xml" -ForegroundColor Red }
	}
	Else
	{
		$Validate = $false
		Write-Host " Missing Variable.xml" -ForegroundColor Red
	}
}

If ($Validate)
{
Write-Host
 Write-Host " Identifying download requirements... "
	If ($DeploymentOnly)
	{
		Write-Host 
		Write-Host "  Collecting server role information..."
		$Servers = @($Variable.Installer.Roles.Role | Where-Object { ($_.Existing -ne "True") -and ($_.SQLCluster -ne "True") } | Sort-Object { $_.Server } -Unique | ForEach-Object { $_.Server })
		$SQLClusters = @($Variable.Installer.Roles.Role | Where-Object { ($_.Existing -ne "True") -and ($_.SQLCluster -eq "True") } | ForEach-Object { $_.Server })
		$SQLClusters | ForEach-Object {
			$SQLCluster = $_
			Write-Host "." -nonewline
			$SQLClusterNodes = $Variable.Installer.SQL.Cluster | Where-Object { $_.Cluster -eq $SQLCluster } | ForEach-Object { $_.Node.Server }
			$Servers += $SQLClusterNodes
		}
		Write-Host "Done" -ForegroundColor Green
		Write-Host "  Collecting SQL version information... "
		# Get SQL versions
		$Installables = @("Windows Server 2012 R2", "Windows Server 2012")
		$Servers | ForEach-Object {
			$Server = $_
			Write-Host "." -nonewline
			$Variable.Installer.Roles.Role | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -ne $null) } | ForEach-Object { $_.Instance } | Sort-Object -Unique | ForEach-Object {
				$Instance = $_
				$Variable.Installer.SQL.Instance | Where-Object { ($_.Server -eq $Server) -and ($_.Instance -eq $Instance) } | ForEach-Object {
					$Installables += $_.Version
				}
			}
		}
		Write-Host "Done" -ForegroundColor Green
		Write-Host "  Collecting role information... " 
		# Get roles
		$MRoles = @()
		$Servers | ForEach-Object {
			$Server = $_
			Write-Host "." -nonewline
			# Get roles for this server
			$MRoles += @($Variable.Installer.Roles.Role | Where-Object { $_.Server -eq $Server } | Where-Object { $_.Existing -ne "True" } | ForEach-Object { $_.Name })
			
			# Get SQL cluster roles for this server
			$Variable.Installer.SQL.Cluster | ForEach-Object {
				$SQLCluster = $_.Cluster
				Write-Host "." -nonewline
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
		Write-Host "Done" -ForegroundColor Green
		Write-Host "  Collecting installables information... "
		# Get installables
		$MRoles | ForEach-Object {
			$Role = $_
			Write-Host "." -nonewline
			$Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Role } | ForEach-Object {
				$_.Prerequisites | ForEach-Object {
					$_.Prerequisite | ForEach-Object {
						$Prerequisite = $_.Name
						If (!($Workflow.Installer.Roles.Role | Where-Object { $_.Name -eq $Prerequisite }))
						{
							$Workflow.Installer.Installables.Installable | ForEach-Object {
								$InstallableName = $_.Name
								If ($_.Install | Where-Object { $_.Name -eq $Prerequisite })
								{
									$Installables += $InstallableName
								}
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
	}
	Else
	{
		Write-Host
		Write-Host "  Collecting software information from Workflow.xml"
		$Installables = $Workflow.Installer.Installables.Installable | ForEach-Object { $_.Name }
	}
	
	$InstallablesData = @()
	$Workflow.Installer.Installables.Installable | ForEach-Object {
		$Installable = $_
		$InstallableName = $_.Name
		If ($Installables | Where-Object { $_ -eq $InstallableName })
		{
			$InstallablesData += $Installable
		}
	}
	
	$WebClient = New-Object System.Net.WebClient
	
	If (Test-Path '.\Variable.xml') { $Variable = [XML] (Get-Content '.\Variable.xml') }
	$SystemDrive = $env:SystemDrive
	$Workflow.Installer.Variable | Where-Object { $_.Name -eq "Download" } | ForEach-Object {
		Invoke-Expression ("`$Download = " + "`"" + $_.Value + "`"")
	}
	If ($Variable)
	{
		$Variable.Installer.Variable | Where-Object { $_.Name -eq "Download" } | ForEach-Object {
			Invoke-Expression ("`$Download = " + "`"" + $_.Value + "`"")
		}
	}
	
	# Count items to download
	$DownloadCount = 0
	$RunCount = 0
	$ZipCount = 0
	$ISOCount = 0
	$RARCount = 0
	$InstallablesData | ForEach-Object {
		If ($_.Download)
		{
			$_.Download | ForEach-Object {
				If ($_.Type -eq "DownloadRun") { $RunCount++ }
				If ($_.URL -ne $null)
				{
					$DownloadCount++
					If ($_.Type -eq "DownloadExtract")
					{
						Switch ($_.Extract.Type)
						{
							"Zip" { $ZipCount++ }
							"ISO" { $ISOCount++ }
							"RAR" { $RARCount++ }
						}
					}
				}
			}
		}
	}
	Write-Host "Done" -ForegroundColor Green
	Write-Host "  Calculating download sizes... "
	# Calculate total download size
	$i = 0
	$DownloadSizeTotal = 0
	$DownloadNeeded = 0
	$InstallablesData | ForEach-Object {
		If ($_.Download)
		{
			$DownloadName = $_.Name
			
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
			$DownloadFolder = Invoke-Expression ($_.SourceFolder)
			$_.Download | ForEach-Object {
				$DownloadItem = $_
				$DownloadType = $_.Type
				$DownloadURL = $_.URL
				$DownloadFile = $_.File
				
				Switch ($DownloadType)
				{
					"DownloadExtract" {
						$ExistingFile = $DownloadItem.Extract.ExistingFile
						If ($GetLatest -eq $true)
						{
							$Skip = $false
							
						}
						Else
						{
							$Skip = Test-Path "$Download\$DownloadFolder\$ExistingFile"
						}
						$DownloadPath = "$Download\Download\$DownloadFolder\$DownloadFile"
					}
					"DownloadRun" {
						$ExistingFile = @($DownloadItem.Run.ExistingFile)[0]
						If ($GetLatest -eq $true)
						{
							$Skip = $false
							
						}
						Else
						{
							$Skip = Test-Path "$Download\$DownloadFolder\$ExistingFile"
						}
						
						$DownloadPath = "$Download\Download\$DownloadFolder\$DownloadFile"
					}
					Default
					{
						$DownloadPath = "$Download\$DownloadFolder\$DownloadFile"
						$ExistingFile = $DownloadItem.Run.ExistingFile
						$Skip = $false
						
					}
				}
				
				If ($_.URL -ne $null)
				{
					$i++
					Write-Progress -id 1 -Activity 'Calculating Total Download Size' -Status "Item $i of $DownloadCount - $DownloadName" -PercentComplete (($i/$DownloadCount) * 100)
					
					# Get item download size
					# Update from Jose Markic
					$WebRequest = [net.WebRequest]::Create($DownloadURL)
					$WebResponseAsync = $WebRequest.GetResponseAsync()
					$DownloadURL > "$env:TEMP\WebResponseAsync.txt"
					$WebResponseAsync > "$env:TEMP\WebResponseAsync.txt"
					if (!($WebResponseAsync.Exception))
					{
						$WebResponseAsync.Dispose()
						$WebResponse = $WebRequest.GetResponse()
						$DownloadSize = $WebResponse.ContentLength
						$WebResponse.Close()
						$WebRequest.Abort()
						$DownloadFileLocation = "Available"
					}
					else
					{
						$WebResponseAsync.Dispose()
						$WebRequest.Abort()
						$DownloadSize = 0
						$Skip = $True
						$DownloadFileLocation = "NA"
						Write-Host "   $DownloadName - $DownloadFile source URL has no data!" -ForegroundColor Red
						If (!(Test-Path $DownloadPath))
						{
							Write-Host "   $DownloadFile must be downloaded manually" -ForegroundColor Yellow
						}
					}
					
					# Delete current item if it is not the correct size
					If (!($Skip) -or ($GetLatest -eq $true))
					{
						If (Test-Path $DownloadPath)
						{
							If (((Get-Item $DownloadPath).Length -ne $DownloadSize) -or ($GetLatest -eq $true))
							{
								Write-Host "   Removing $DownloadPath ... " -NoNewLine
								Try
								{
									Remove-Item $DownloadPath
								}
								Catch
								{
									Write-Host "Error deleting $DownloadPath" -ForegroundColor Red
								}
								Write-Host
								$DownloadSizeTotal = $DownloadSizeTotal + $DownloadSize
								$DownloadNeeded++
							}
						}
						Else
						{
							If (!(Test-Path "$Download\$DownloadFolder")) { New-Item -Path "$Download\$DownloadFolder" -ItemType Directory | Out-Null }
							$DownloadSizeTotal = $DownloadSizeTotal + $DownloadSize
							$DownloadNeeded++
						}
					}
				}
				Else
				{
					If (!($DownloadName.Contains("Prerequisites")))
					{
						If (Test-Path "$Download\$DownloadFolder\$DownloadFile")
						{
							$DownloadFileType = $DownloadFile.Split(".")[$DownloadFile.Split(".").Count - 1]
							Switch ($DownloadFileType)
							{
								"exe" {
									$DownloadFileVersion = $DownloadItem.FileVersion.Split("/")
									$DownloadFileVersion | ForEach-Object { If (!((Get-Item "$Download\$DownloadFolder\$DownloadFile").VersionInfo.ProductVersion -eq $_)) { $Result = $true } }
									If ($Result)
									{
										Write-Host "   $DownloadName must be downloaded manually" -ForegroundColor Yellow
									}
									Break
								}
								Default
								{
									$DownloadFileSize = $DownloadItem.FileSize.Split("/")
									$DownloadFileSize | ForEach-Object { If (!((Get-Item "$Download\$DownloadFolder\$DownloadFile").Length -eq $_)) { $Result = $true } }
									If ($Result)
									{
										
										Write-Host "   $DownloadName must be downloaded manually" -ForegroundColor Yellow
									}
								}
							}
						}
						Else
						{
							Write-Host "   $DownloadName must be downloaded manually" -ForegroundColor Yellow
						}
					}
				}
			}
		}
	}
	$DownloadSizeTotalinMB = [System.Math]::Round(($DownloadSizeTotal/1024/1024), 2)


	If ($DownloadSizeTotalInMB -ne 0)
	{
		Write-Host " Downloading content... "
		# Download item
		$i = 0
		$DownloadedSize = 0
		Write-Progress -id 2 -Activity 'Starting Download'
		$InstallablesData | ForEach-Object {
			If ($_.Download)
			{
				$DownloadName = $_.Name
				$ShortDownloadFolder = Invoke-Expression ($_.SourceFolder)
				$_.Download | ForEach-Object {
					If ($_.URL -ne $null)
					{
						$DownloadItem = $_
						$DownloadFolder = $ShortDownloadFolder
						$DownloadType = $_.Type
						$DownloadURL = $_.URL
						$DownloadFile = $_.File
						
						If ($WebClient.IsBusy) { Start-Sleep 1 }
						
						Switch ($DownloadType)
						{
							"DownloadExtract" {
								$ExistingFile = $DownloadItem.Extract.ExistingFile
								If ($GetLatest -eq $true)
								{
									$Skip = $false
									
								}
								Else
								{
									$Skip = Test-Path "$Download\$DownloadFolder\$ExistingFile"
								}
								
								$DownloadPath = "$Download\Download\$DownloadFolder\$DownloadFile"
								$DownloadFolder = "$Download\Download\$DownloadFolder"
							}
							"DownloadRun" {
								$ExistingFile = @($DownloadItem.Run.ExistingFile)[0]
								If ($GetLatest -eq $true)
								{
									$Skip = $false
									
								}
								Else
								{
									$Skip = Test-Path "$Download\$DownloadFolder\$ExistingFile"
								}
								
								$DownloadPath = "$Download\Download\$DownloadFolder\$DownloadFile"
								$DownloadFolder = "$Download\Download\$DownloadFolder"
							}
							Default
							{
								$DownloadPath = "$Download\$DownloadFolder\$DownloadFile"
								$DownloadFolder = "$Download\$DownloadFolder"
								$Skip = $false
							}
						}
						# If current item does not exist
						If (!(Test-Path $DownloadPath) -and !($Skip))
						{
							$i++
							
							$DownloadCurrentTotal = 0
							$DownloadCurrentTotalinMB = 0
							
							# Get item download size
							# Update from Jose Markic
							$WebRequest = [net.WebRequest]::Create($DownloadURL)
							$WebResponseAsync = $WebRequest.GetResponseAsync()
							$DownloadURL > "$env:TEMP\WebResponseAsync.txt"
							$WebResponseAsync > "$env:TEMP\WebResponseAsync.txt"
							if (!($WebResponseAsync.Exception))
							{
								$WebResponseAsync.Dispose()
								$WebResponse = $WebRequest.GetResponse()
								$DownloadSize = $WebResponse.ContentLength
								$WebResponse.Close()
								$WebRequest.Abort()
								$DownloadSizeInMB = [System.Math]::Round(($DownloadSize/1024/1024), 2)
								$DownloadFileLocation = "Available"
							}
							else
							{
								$WebResponseAsync.Dispose()
								$WebRequest.Abort()
								$DownloadSizeInMB = 0
								$DownloadFileLocation = "NA"
								Write-Host "   $DownloadURL has no data!" -ForegroundColor Red
							}
							
							
							# Create folder for item
							If (!(Test-Path $DownloadFolder))
							{
								New-Item -Path $DownloadFolder -ItemType Directory | Out-Null
							}
							
							# Download item
							try
							{
								$WebClient.DownloadFileAsync($DownloadURL, $DownloadPath)
							}
							Catch
							{
								Write-Host $Error
							}
							While (!(Test-Path $DownloadPath)) { Start-Sleep 1 }
							While ((Get-Item $DownloadPath).Length -lt $DownloadSize)
							{
								$DownloadCurrentSize = (Get-Item $DownloadPath).Length
								$DownloadCurrentSizeinMB = [System.Math]::Round(($DownloadCurrentSize/1024/1024), 2)
								$DownloadCurrentTotal = $DownloadedSize + $DownloadCurrentSize
								$DownloadCurrentTotalinMB = [System.Math]::Round(($DownloadCurrentTotal/1024/1024), 2)
								Write-Progress -id 1 -Activity "Downloading Item $i of $DownloadNeeded" -Status "$DownloadCurrentTotalinMB of $DownloadSizeTotalinMB MB" -PercentComplete (($DownloadCurrentTotal/$DownloadSizeTotal) * 100)
								Write-Progress -id 2 -Activity "Downloading $DownloadName" -Status "$DownloadCurrentSizeinMB of $DownloadSizeInMB MB" -PercentComplete (((Get-Item $DownloadPath).Length / $DownloadSize) * 100)
								Start-Sleep 1
							}
							$DownloadedSize = $DownloadedSize + (Get-Item $DownloadPath).Length
						}
					}
				}
			}
		}
	}
	Write-Host 
	Write-Host " Processing downloads... "
	# Zip Extract
	If ($ZipCount -ge 1)
	{
		Write-Progress -id 1 -Activity 'Starting Zip Extract'
		$i = 0
		$Shell = New-Object -ComObject shell.application
		$InstallablesData | ForEach-Object {
			If ($_.Download -and ($_.Download.Type -eq "DownloadExtract") -and ($_.Download.Extract.Type -eq "Zip"))
			{
				$DownloadName = $_.Name
				$DownloadFolder = Invoke-Expression ($_.SourceFolder)
				$_.Download | ForEach-Object {
					$i++
					$DownloadFile = $_.File
					$ExistingFile = $_.Extract.ExistingFile
					Write-Progress -id 1 -Activity "Extracting zip $i of $ZipCount" -PercentComplete ((($i - 1)/$ZipCount) * 100)
					Write-Progress -id 2 -Activity "Extracting zip $DownloadName" -PercentComplete ((($i - 1)/$ZipCount) * 100)
					If (!(Test-Path "$Download\$DownloadFolder\$ExistingFile"))
					{
						$DownloadFileRename = $false
						If ($DownloadFile.Substring($DownloadFile.Length - 3) -eq "exe")
						{
							$DownloadFileRename = $true
							Rename-Item -Path "$Download\Download\$DownloadFolder\$DownloadFile" -NewName ($DownloadFile.Substring(0, $DownloadFile.Length - 3) + "zip")
							$DownloadFile = $DownloadFile.Substring(0, $DownloadFile.Length - 3) + "zip"
							Start-Sleep 1
						}
						$Zip = $Shell.Namespace("$Download\Download\$DownloadFolder\$DownloadFile")
						$Unzip = $Shell.Namespace("$Download\$DownloadFolder")
						$Unzip.CopyHere($Zip.Items(), 16)
						If ($DownloadFileRename)
						{
							Rename-Item -Path "$Download\Download\$DownloadFolder\$DownloadFile" -NewName ($DownloadFile.Substring(0, $DownloadFile.Length - 3) + "exe")
						}
					}
				}
			}
		}
	}
	
	# MSI Extract
	If ($MSICount -ge 1)
	{
		Write-Progress -id 1 -Activity 'Starting MSI Extract'
		$i = 0
		$InstallablesData | ForEach-Object {
			If ($_.Download -and ($_.Download.Type -eq "DownloadExtract") -and ($_.Download.Extract.Type -eq "MSI"))
			{
				$DownloadName = $_.Name
				$DownloadFolder = Invoke-Expression ($_.SourceFolder)
				$_.Download | ForEach-Object {
					$i++
					$DownloadFile = $_.File
					$ExistingFile = $_.Extract.ExistingFile
					Write-Progress -id 1 -Activity "Extracting MSI $i of $MSICount" -PercentComplete ((($i - 1)/$MSICount) * 100)
					Write-Progress -id 2 -Activity "Extracting MSI $DownloadName" -PercentComplete ((($i - 1)/$MSICount) * 100)
					If (!(Test-Path "$Download\$DownloadFolder\$ExistingFile"))
					{
						if (Test-Path "$Download\Download\$DownloadFolder\$DownloadFile")
						{
							dir "$Download\Download\$DownloadFolder" | where { -Not $_.PsIscontainer -AND $_.name -match " " } | foreach {
								$New = $_.name.Replace(" ", "_")
								if (!(Test-Path -Path "$Download\$DownloadFolder\$New")) { Rename-Item -path $_.Fullname -newname $New }
							}
						}
						$ExtractorExe = "c:\Windows\System32\cmd.exe"
						Start-Process -FilePath "$ExtractorExe" -ArgumentList "/c msiexec.exe /a $Download\Download\$DownloadFolder\$ExistingFile /qn TARGETDIR=$Download\$DownloadFolder" -Wait -WindowStyle Hidden
					}
				}
			}
		}
	}
	
	
	# ISO Extract
	If ($ISOCount -ge 1)
	{
		Write-Progress -id 1 -Activity 'Starting ISO Extract'
		$i = 0
		$InstallablesData | ForEach-Object {
			If ($_.Download -and ($_.Download.Type -eq "DownloadExtract") -and ($_.Download.Extract.Type -eq "ISO"))
			{
				$DownloadName = $_.Name
				$DownloadFolder = Invoke-Expression ($_.SourceFolder)
				$_.Download | ForEach-Object {
					$i++
					$DownloadFile = $_.File
					$ExistingFile = $_.Extract.ExistingFile
					Write-Progress -id 1 -Activity "Extracting ISO $i of $ISOCount" -PercentComplete ((($i - 1)/$ISOCount) * 100)
					Write-Progress -id 2 -Activity "Extracting ISO $DownloadName" -PercentComplete ((($i - 1)/$ISOCount) * 100)
					If (!(Test-Path "$Download\$DownloadFolder\$ExistingFile"))
					{
						$ExtractSize = (Mount-DiskImage -ImagePath "$Download\Download\$DownloadFolder\$DownloadFile" -PassThru).Size
						$ExtractDrive = (Get-Volume | Where-Object { ($_.DriveType -eq 'CD-ROM') -and ($_.Size -eq $ExtractSize) }).DriveLetter
						$ExtractDrive = $ExtractDrive + ":"
						If ($_.Extract.Files)
						{
							$_.Extract.Files.File | ForEach-Object {
								Start-Process -FilePath 'robocopy.exe' -ArgumentList "$ExtractDrive $Download\$DownloadFolder $_" -Wait -WindowStyle Hidden
							}
						}
						Else
						{
							Start-Process -FilePath 'robocopy.exe' -ArgumentList "$ExtractDrive $Download\$DownloadFolder /e" -Wait -WindowStyle Hidden
						}
						Dismount-DiskImage -ImagePath "$Download\Download\$DownloadFolder\$DownloadFile"
					}
				}
			}
		}
	}
	
	# RAR Extract
	If ($RARCount -ge 1)
	{
		If ($Extractor)
		{
			Write-Progress -id 1 -Activity 'Starting RAR Extract'
			$i = 0
			$InstallablesData | ForEach-Object {
				If ($_.Download -and ($_.Download.Type -eq "DownloadExtract") -and ($_.Download.Extract.Type -eq "RAR"))
				{
					$DownloadName = $_.Name
					$DownloadFolder = Invoke-Expression ($_.SourceFolder)
					$_.Download | ForEach-Object {
						$i++
						$DownloadFile = $_.File
						$ExistingFile = $_.Extract.ExistingFile
						Write-Progress -id 1 -Activity "Extracting RAR $i of $RARCount" -PercentComplete ((($i - 1)/$RARCount) * 100)
						Write-Progress -id 2 -Activity "Extracting RAR $DownloadName" -PercentComplete ((($i - 1)/$RARCount) * 100)
						If (!(Test-Path "$Download\$DownloadFolder"))
						{
							New-Item -Path "$Download\$DownloadFolder" -ItemType Directory | Out-Null
						}
						If (!(Test-Path "$Download\$DownloadFolder\$ExistingFile"))
						{
							Switch ($Extractor)
							{
								"WinRAR" { Start-Process -FilePath "$ExtractorExe" -ArgumentList "x $Download\Download\$DownloadFolder\$DownloadFile $Download\$DownloadFolder" -Wait -WindowStyle Hidden }
								"7-Zip" { Start-Process -FilePath "$ExtractorExe" -ArgumentList "x -o$Download\$DownloadFolder $Download\Download\$DownloadFolder\$DownloadFile" -Wait -WindowStyle Hidden }
							}
						}
					}
				}
			}
		}
	}
	
	# Run
	If ($RunCount -ge 1)
	{
		Write-Progress -id 1 -Activity 'Starting Run'
		$i = 0
		$InstallablesData | ForEach-Object {
			If ($_.Download -and ($_.Download.Type -eq "DownloadRun"))
			{
				$DownloadName = $_.Name
				$DownloadFolder = Invoke-Expression ($_.SourceFolder)
				$_.Download | ForEach-Object {
					$i++
					$DownloadFile = $_.File
					$_.Run | Where-Object { $_ -ne $null } | ForEach-Object {
						$DownloadCommand = $_.Command
						$DownloadArgument = $_.Argument
						$ExistingFile = $_.ExistingFile
						Write-Progress -id 1 -Activity "Running $i of $RunCount" -PercentComplete ((($i - 1)/$RunCount) * 100)
						Write-Progress -id 2 -Activity "Running $DownloadName" -PercentComplete ((($i - 1)/$RunCount) * 100)
						If (($ExistingFile -eq $null) -or !(Test-Path "$Download\$DownloadFolder\$ExistingFile"))
						{
							Invoke-Expression ("`$DownloadCommand" + " = `"" + $DownloadCommand + "`"")
							Invoke-Expression ("`$DownloadArgument" + " = `"" + $DownloadArgument + "`"")
							If ((Test-Path "$DownloadCommand") -or ($DownloadCommand -eq "cmd.exe"))
							{
								If ($DownloadArgument -eq "")
								{
									Start-Process -FilePath $DownloadCommand -Wait -WindowStyle Hidden
								}
								Else
								{
									Start-Process -FilePath $DownloadCommand -ArgumentList $DownloadArgument -Wait -WindowStyle Hidden
								}
							}
						}
					}
				}
			}
		}
	}
}

Write-Host
Write-Host " Unblocking files... " -ForegroundColor White -NoNewLine
Get-ChildItem -Path "$Download" -Recurse | ForEach-Object { Unblock-File -Path $_.FullName }
Write-Host "Complete" -ForegroundColor Green

$EndTime = Get-Date
$TotalExecTime = $EndTime - $StartTime
Write-Host "`n End time:" (Get-Date)
Write-Host " Script execution time:`n $TotalExecTime"
Write-Host