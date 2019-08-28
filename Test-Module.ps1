<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2017 v5.4.145
	 Created on:   	2018-02-10 7:06 PM
	 Created by:   	MaximeB
	 Organization: 	MB_Tools
	 Filename:     	Test-Module.ps1
	===========================================================================
	.DESCRIPTION
	The Test-Module.ps1 script lets you test the functions and other features of
	your module in your PowerShell Studio module project. It's part of your project,
	but it is not included in your module.

	In this test script, import the module (be careful to import the correct version)
	and write commands that test the module features. You can include Pester
	tests, too.

	To run the script, click Run or Run in Console. Or, when working on any file
	in the project, click Home\Run or Home\Run in Console, or in the Project pane, 
	right-click the project name, and then click Run Project.
#>


#Explicitly import the module for testing
Import-Module 'TeamViewerPSModules'

#Run each module function

#Sample Pester Test
#Describe "Test TeamViewerPSModules" {
#	It "tests Write-HellowWorld" {
#		Write-HelloWorld | Should BeExactly "Hello World"
#	}	
#}
$global:TVToken = ""
#Get-TVUsers | Where-Object {$_.name -like "*bassem*"}
function Remove-TVDuplicateDevices
{
	[CmdletBinding(ConfirmImpact = 'Medium',
				   PositionalBinding = $false,
				   SupportsPaging = $true,
				   SupportsShouldProcess = $true)]
	param
	(
		$Token
	)
	
	if ($global:TVToken)
	{
		$token = $global:TVToken
	}
	elseif ($token)
	{
		$token = $token
	}
	else
	{
		Write-Output "You need to Set the Token"
		break
	}
	
	$Devices = Get-TVDevices
	$Devices | Out-File "$env:APPDATA\TeamViewerAllDevices.txt"
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $Token")
	$Array = @()
	
	[int]$Count = ($Devices).count
	$Start = 0
	
	foreach ($Device in $Devices)
	{
		$DeviceAlias = $Device.Alias
		$CheckDuplicates = $Devices | Where-Object { $_.alias -like "*$DeviceAlias*" }
		$percent = [math]::Round((($Start / $Count) * 100))
		if ($CheckDuplicates.count -gt 1)
		{
			$CheckArray = $Array | Where-Object { $_ -like "*$DeviceAlias*" }
			if ([string]::IsNullOrEmpty($CheckArray) -eq $true)
			{
				$Array += $DeviceAlias
			}
		}
		
		Write-Progress -Activity "Search in Progress" -Status "$percent% Complete:" -PercentComplete $percent
		$Start += 1
	}
	
	
	[int]$Count = ($Array).count
	$Start = 0
	<#
	foreach ($Alias in $Array)
	{
		$CheckDuplicates = Get-TVDeviceIdFromAlias -alias $Alias
		$LastSeenValue = $CheckDuplicates | Measure-Object -Maximum
		$i = 0
		$percent = [math]::Round((($Start / $Count) * 100))
		foreach ($item in $CheckDuplicates)
		{
			if ($item -ne $LastSeenValue.Maximum)
			{
				$devicesID = $item
				$Device = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/devices/$devicesID" -Method get -Headers $header -ContentType application/json -ErrorAction SilentlyContinue
				if ($Device.devices.device_id)
				{
					$Device.devices
					#Delete-TVDevice -DeviceID $devicesID
				}
				
			}
			Write-Progress -Activity "Delete Duplicates in Progress" -Status "Deleting: $item" -PercentComplete $percent
			$Start += 1
			$i++
		}
	}
	#>
}

Remove-TVDuplicateDevices