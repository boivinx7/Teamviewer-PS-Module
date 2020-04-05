<#
	.SYNOPSIS
		Set Teamviewer Token for All Other Functions, Also Test the connection to Teamviewer API

	.DESCRIPTION
		Use to Set Teamviewer Token For All Other Functions.
		Will Also use the GET /api/v1/ping API Function

	.PARAMETER UserToken
		Is the User Level Token that you can create from the Teamviewer Management Console
		Use Script and Not App Token and User not Company Token.

	.EXAMPLE
		PS C:\> Set-TVToken -UserToken $value1

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Set-TVToken {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		[Alias('Token')]
		[string]$UserToken
	)

	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $UserToken")
	$TokenTest = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/ping" -Method GET -Headers $header -ContentType application/json
	if ($TokenTest.token_valid -eq $true) {
		$header.Add("authorization", "Bearer  $token")
		if ($PSCmdlet.ShouldProcess("$UserToken" , "Set-TVToken")) {
			Write-Output "Teamviewer Token Is Working and Set"
			$global:TVToken = $UserToken
		}
	}
	else {
		Write-Output "Teamviewer Token not working"
	}
}

<#
	.SYNOPSIS
		Retrieves account information of the account associated with the access token.

	.DESCRIPTION
		Retrieves account information of the account associated with the access token.

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Get-TVAccountInformation

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVAccountInformation {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	if ($PSCmdlet.ShouldProcess("$token" , "Get-TVAccountInformation")) {
		$Account = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/account" -Method GET -Headers $header -ContentType application/json
		$Account
	}
}

<#
	.SYNOPSIS
		Gets Teamviewer Device ID from Alias Can be Portion of the alias

	.DESCRIPTION
		Get the ID of a Teamviewer Device from Alias.

	.PARAMETER alias
		Is the Name of the Device seen in all consoles

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Get-TVDeviceIdFromAlias -alias $value1

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVDeviceIdFromAlias {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		$alias,
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	if ($PSCmdlet.ShouldProcess("$alias" , "Get-TVDeviceIdFromAlias")) {
		$Device = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/devices?full_list=true" -Method GET -Headers $header -ContentType application/json
		$DeviceInformation = $Device.devices | Where-Object { $_.alias -like "*$alias*" }
		$DeviceInformation.device_id
	}
}

<#
	.SYNOPSIS
		Gets All Teamviewer Device Info from Alias Can be Portion of the alias

	.DESCRIPTION
		Get all possible information of a Device from it's alias

	.PARAMETER alias
		Is the Name of the Device seen in all console

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Get-TVDeviceInfoFromAlias -alias $value1

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVDeviceInfoFromAlias {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		$alias,
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$Device = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/devices?full_list=true" -Method GET -Headers $header -ContentType application/json
	$DeviceInformation = $Device.devices | Where-Object { $_.alias -like "*$alias*" }
	$DeviceInformation
}

<#
	.SYNOPSIS
		Get the List of All Registered Devices And there information

	.DESCRIPTION
		Returns a list of devices in the user's computers & contacts list

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Get-TVDevices

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVDevices {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$Devices = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/devices?full_list=true" -Method GET -Headers $header -ContentType application/json
	$Devices.devices
}

<#
	.SYNOPSIS
		Get Teamviewer User ID From Email Address

	.DESCRIPTION
		Get Teamviewer User ID From Email Address

	.PARAMETER UserEmail
		email address of the Account you are looking for

	.PARAMETER Token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Get-TVUserIDFromEmail -UserEmail $value1

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVUserIDFromEmail {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		$UserEmail,
		$Token
	)

	if ($global:TVToken) {
		$Token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $Token")
	$Users = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/users?email=$UserEmail" -Method GET -Headers $header -ContentType application/json
	$UserInformation = $Users.users | Where-Object { $_.email -like "*$UserEmails*" }
	$UserInformation.id
}

<#
	.SYNOPSIS
		Get Teamviewer User Information From User ID

	.DESCRIPTION
		Get Teamviewer User Information From User ID

	.PARAMETER UserID
		Teamviewer User ID.

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Get-TVUserInformation -UserID $value1

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVUserInformation {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		$UserID,
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$Users = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/users/$UserID" -Method GET -Headers $header -ContentType application/json
	$Users
}

<#
	.SYNOPSIS
		Get List of All Users information in Teamviewer Account

	.DESCRIPTION
		Lists all users in a company. The list can be filtered with additional parameters. The function can also return
		a list containing all information about the users. This data is the same as when using GET /users/uID for
		each of these users.

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Get-TVUsers

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVUsers {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$Users = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/users?full_list=true" -Method GET -Headers $header -ContentType application/json
	$Users.Users
}

<#
	.SYNOPSIS
		Get Teamviewer Group ID From Group Name

	.DESCRIPTION
		Get Teamviewer Group ID From Group Name

	.PARAMETER name
		Teamviewer Group Name

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Get-TVGroupIDFromName -name $value1

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVGroupIDFromName {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		$name,
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$Group = Invoke-RestMethod -Uri "https://webapi.teamviewer.com//api/v1/groups?name=$name" -Method get -Headers $header -ContentType application/json
	$Group.groups.id
}


<#
	.SYNOPSIS
		Get List of teamviewer Groups

	.DESCRIPTION
		Returns a list of groups

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Get-TVGroups

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVGroups {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$Group = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/groups" -Method get -Headers $header -ContentType application/json
	$Group.groups
}

<#
	.SYNOPSIS
		Get Teamviewer Group Details from Group ID

	.DESCRIPTION
		Get Teamviewer Group Details from Group ID.

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.PARAMETER GroupID
		Teamviewer Group ID

	.EXAMPLE
		PS C:\> Get-TVGroupDetailFromGroupID -GroupID $value1

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVGroupDetailFromGroupID {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		$token,
		[Parameter(Mandatory = $true)]
		$GroupID
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	if ($global:TVToken) {
		$token = $global:TVToken
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$Group = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/groups/$groupID" -Method get -Headers $header -ContentType application/json
	$Group
}

<#
	.SYNOPSIS
		Share Teamviewer Group

	.DESCRIPTION
		Shares a group with the given users. Will not change the share state with other users, but it is possible to
		overwrite the permissions for existing shares.

	.PARAMETER GroupID
		Teamviewer Group ID

	.PARAMETER GroupPermissions
		Options are:
		read, readwrite and full

	.PARAMETER UserId
		Teamviewer User ID

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Share-TVGroup

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Add-TVGroupShare {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$GroupID,
		[Parameter(Mandatory = $true)]
		[ValidateSet('read', 'readwrite', 'full')]
		[string]$GroupPermissions,
		[Parameter(Mandatory = $true)]
		[string]$UserID,
		[string]$Token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$body = @{
		Users = @(
			@{
				userid      = "$UserId"
				permissions = "$GroupPermissions"
			}
		)
	} | ConvertTo-Json
	if ($PSCmdlet.ShouldProcess("$GroupID" , "Add-TVGroupShare")) {
		Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/groups/$GroupID/share_group" -Method Post -Headers $header -ContentType application/json -Body "$body"
	}
}

<#
	.SYNOPSIS
		Unshares a group from certain users.

	.DESCRIPTION
		Unshares a group from certain users.
		This function supports the -WhatIf parameter

	.PARAMETER GroupID
		Teamviewer Group ID

	.PARAMETER UserIDs
		Teamviewer User ID

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Unshare-TVGroup -GroupID $value1 -UserID $value2

	.EXAMPLE
		PS C:\> Unshare-TVGroup -GroupID $value1 -UserID $value2 -WhatIf

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Remove-TVGroupShare {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$GroupID,
		[Parameter(Mandatory = $true)]
		[array]$UserIDs,
		$Token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$body = [ordered]@{
		users = $UserIDs
	} | ConvertTo-Json
	if ($PSCmdlet.ShouldProcess("$groupID" , "Remove-TVGroupShare")) {
		Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/groups/$groupID/unshare_group" -Method Post -Headers $header -ContentType application/json -Body "$body"
	}
}

<#
	.SYNOPSIS
		Create new Teamviewer company member

	.DESCRIPTION
		A detailed description of the Create-TVUser function.

	.PARAMETER UserEmail
		Email of that user. Will be used for login.

	.PARAMETER defaultUserPermissions
		Default Password Set for new user

	.PARAMETER DefaultUserLanguage
		Language code for the user. Will be used for the welcome email

	.PARAMETER defaultUserPassword
		Predefined password for the user. Will be used for login. The predefined
		password is optional. If Single Sign-On is used, the password parameter should be empty

	.PARAMETER UserFullName
		Name of the new user.

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Create-TVUser -UserEmail 'User.name@Company.com' -defaultUserPermissions ViewOwnConnections -DefaultUserLanguage en -defaultUserPassword 'SomePassword' -UserFullName 'User Name'

	.NOTES
		Additional information about the function.
#>
function Add-TVUser {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$UserEmail,
		[Parameter(Mandatory = $false)]
		[ValidateSet('Default', 'ManageAdmins', 'ManageUsers', 'ShareOwnGroups', 'ViewAllConnections', 'ViewOwnConnections', 'EditConnections', 'DeleteConnections', 'EditFullProfile', 'AllowPasswordChange', 'ManagePolicies', 'AssignPolicies', 'AcknowledgeAllAlerts', 'AcknowledgeOwnAlerts', 'ViewAllAssets', 'ViewOwnAssets', 'EditAllCustomModuleConfigs', 'EditOwnCustomModuleConfigs')]
		$defaultUserPermissions = 'Default',
		[Parameter(Mandatory = $true)]
		[ValidateSet('id', 'cs', 'da', 'de', 'en', 'es', 'fr', 'hr', 'it', 'lt', 'hu', 'nl', 'no', 'pl', 'pt', 'ro', 'sk', 'sr', 'fi', 'sv', 'vi', 'tr', 'el', 'bg', 'uk', 'ru', 'th', 'ko', 'zh_TW', 'zh_CN', 'ja')]
		[string]$DefaultUserLanguage,
		[Parameter(Mandatory = $false)]
		[string]$defaultUserPassword,
		[Parameter(Mandatory = $true)]
		[string]$UserFullName,
		$token
	)

	if ($defaultUserPermissions -eq "ManageAdmins") {
		$defaultUserPermissions = @("ManageAdmins", "ManageUsers", "ShareOwnGroups", "EditFullProfile", "ViewAllConnections", "ViewOwnConnections", "EditConnections", "DeleteConnections", "ManagePolicies", "AssignPolicies", "AcknowledgeAllAlerts", "AcknowledgeOwnAlerts", "ViewAllAssets", "ViewOwnAssets", "EditAllCustomModuleConfigs", "EditOwnCustomModuleConfigs")
	}
	elseif ($defaultUserPermissions -eq "ManageUsers") {
		$defaultUserPermissions = @("ManageUsers", "ShareOwnGroups", "EditFullProfile", "ViewAllConnections", "ViewOwnConnections", "EditConnections", "DeleteConnections", "ManagePolicies", "AssignPolicies", "AcknowledgeAllAlerts", "AcknowledgeOwnAlerts", "ViewAllAssets", "ViewOwnAssets", "EditAllCustomModuleConfigs", "EditOwnCustomModuleConfigs")
	}
	elseif ($defaultUserPermissions -eq "ViewAllConnections") {
		$defaultUserPermissions = @("ViewAllConnections", "ViewOwnConnections")
	}
	elseif ($defaultUserPermissions -eq "ManagePolicies") {
		$defaultUserPermissions = @("ManagePolicies", "AssignPolicies", "AcknowledgeAllAlerts", "AcknowledgeOwnAlerts")
	}
	elseif ($defaultUserPermissions -eq "AssignPolicies") {
		$defaultUserPermissions = @("AssignPolicies", "AcknowledgeAllAlerts", "AcknowledgeOwnAlerts")
	}
	elseif ($defaultUserPermissions -eq "AcknowledgeAllAlerts") {
		$defaultUserPermissions = @("AcknowledgeAllAlerts", "AcknowledgeOwnAlerts")
	}
	elseif ($defaultUserPermissions -eq "ViewOwnAssets") {
		$defaultUserPermissions = @("ViewAllAssets", "ViewOwnAssets")
	}
	elseif ($defaultUserPermissions -eq "EditAllCustomModuleConfigs") {
		$defaultUserPermissions = @("EditAllCustomModuleConfigs", "EditOwnCustomModuleConfigs")
	}
	elseif ($defaultUserPermissions -eq "Default") {
		$defaultUserPermissions = @("ShareOwnGroups", "ViewOwnConnections", "EditConnections", "EditFullProfile")
	}

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$body = (@{
			email      = $UserEmail
			password   = $defaultUserPassword
			name       = $UserFullName
			language   = $defaultUserLanguage
			permission = $defaultUserPermissions
		}) | ConvertTo-Json
		if ($PSCmdlet.ShouldProcess("$body" , "Add-TVUser")) {
			Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/users" -Method Post -Headers $header -ContentType application/json -Body $body
		}
}

<#
	.SYNOPSIS
		Deletes a device from the computers & contacts list

	.DESCRIPTION
		Deletes a device from the computers & contacts list. An error is returned if either
		• a device with the given dID does not exist in the current user's computers & contact list.
		• the user does not have sufficient rights to remove the specified contact from a shared group.
		This function supports the -WhatIf parameter

	.PARAMETER DeviceID
		Teamviewer Device or Contact ID

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Delete-TVDevice -DeviceID $value1

	.EXAMPLE
		PS C:\> Delete-TVDevice -DeviceID $value2 -WhatIf


	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Remove-TVDevice {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		$DeviceID,
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	if ($PSCmdlet.ShouldProcess("$DeviceID" , "Remove-TVDevice")) {
		Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/devices/$deviceID" -Method Delete -Headers $header -ContentType application/json
	}
}

<#
	.SYNOPSIS
		3

	.DESCRIPTION
		A detailed description of the Set-TVPolicyAssignement function.

	.PARAMETER DeviceID
		ID of Teamviewer Device to assign policy to

	.PARAMETER PolicyID
		ID of Teamviewer Policy be assign to device

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.PARAMETER Password
		A description of the Password parameter.

	.EXAMPLE
		PS C:\> Assign-TVPolicy -DeviceID $value1 -PolicyID $value2

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Set-TVPolicyAssignement {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		$DeviceID,
		[Parameter(Mandatory = $true)]
		$PolicyID,
		$token,
		$Password
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$body = (@{
			policy_id = $PolicyID
			password  = $password
		}) | ConvertTo-Json
		if ($PSCmdlet.ShouldProcess("$DeviceID" , "Set-TVPolicyAssignement")) {
			Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/devices/$DeviceID" -Method PUT -Headers $header -ContentType application/json -Body $body
		}
}

<#
	.SYNOPSIS
		Use to Assign Group to Devices

	.DESCRIPTION
		Use to Change Device from Group

	.PARAMETER deviceID
		ID of Teamviewer Device to move to Group

	.PARAMETER groupID
		ID of the group the device will be moved to. May not be used together

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Assign-TVGroup -DeviceID $Value1 -GroupID $Value2

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Set-TVGroupAssignement {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		$DeviceID,
		[Parameter(Mandatory = $true)]
		$GroupID,
		$Token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$body = (@{
			groupid = $groupID
		}) | ConvertTo-Json
		if ($PSCmdlet.ShouldProcess("$deviceID" , "Set-TVGroupAssignement")) {
			Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/devices/$deviceID" -Method PUT -Headers $header -ContentType application/json -Body $body
		}
}

<#
	.SYNOPSIS
		Get Teamviewer Policy ID from Name

	.DESCRIPTION
		A detailed description of the Get-TVPolicyIdFromName function.

	.PARAMETER policyname
		name of Teamviewer Policy

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
				PS C:\> Get-TVPolicyIdFromName

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVPolicyIdFromName {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		$policyname,
		$token
	)
	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$policies = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/teamviewerpolicies" -Method get -Headers $header -ContentType application/json
	$policieinfo = $policies.policies | Where-Object { $_.name -eq "$policyname" }
	$policieinfo.policy_id
}

<#
	.SYNOPSIS
		– List of policies

	.DESCRIPTION
		Lists all policies created by the account. Use in combination with PUT /api/v1/teamviewerpolicies/<policy_id>
		to modify a policy..

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Get-TVPolicies

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Get-TVPolicies {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		$token
	)
	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$policies = Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/teamviewerpolicies" -Method get -Headers $header -ContentType application/json
	$policies.policies
}

<#
	.SYNOPSIS
		Cleanup old offline devices

	.DESCRIPTION
		Used to cleanup old Offline devices from console
		Can use (Get-Date).AddMonths(-5)
		To Create Variable for old devices
		will only work on offline devices

	.PARAMETER LastSeen
		Use the Last Seen Date to Delete Old Offline Devices
		Last Seen Only Exist if Device has been offline for a certain time.
		Must use Date Time Paramater
		Will be force put in format yyyy-MM-dd

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> $Date = (Get-Date).AddMonths(-5)
		PS C:\> Cleanup-TVDevices -LastSeen $Date -token $Usertoken

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Remove-TVOldDevices {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		[datetime]$LastSeen,
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$LastSeen = ($LastSeen).ToString("yyyy-MM-dd")
	$Device = Get-TVDevices -token $token
	$DeviceInformation = $Device.devices | Where-Object { $_.online_state -eq "offline" -and $_.last_seen -lt "$LastSeen*" }
	foreach ($item in $DeviceInformation) {
		if ($item.last_seen) {
			Remove-TVDevice -deviceID $item.device_id -token $token
		}

	}
}


<#
	.SYNOPSIS
		Switch All Devices from a Group to another

	.DESCRIPTION
		Will get all devices in a group and move it to another one

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.PARAMETER PreviousGroupName
		name of the Old Group that the devices are in

	.PARAMETER NewGroupName
		name of the new group to put the devices in

	.PARAMETER DeleteOldGroup
		Will Delete the old Group once emptied

	.EXAMPLE
		PS C:\> Switch-TVDevicesGroups -PreviousGroupName $value1 -NewGroupName $value2

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Switch-TVDevicesGroups {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		$Token,
		[Parameter(Mandatory = $true)]
		$PreviousGroupName,
		[Parameter(Mandatory = $true)]
		$NewGroupName,
		[bool]$DeleteOldGroup
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}

	$OldTvgroupID = Get-TVGroupIDFromName -name $PreviousGroupName -token $token

	$NewTvgroupID = Get-TVGroupIDFromName -name $NewGroupName -token $token

	$Devices = (Get-TVDevices -token $token).devices | Where-Object { $_.groupid -eq $OldTvgroupID }
	$Devices = $Devices.device_id
	[int]$Count = ($Devices).count
	$Start = 0
	foreach ($DID in $Devices) {
		$percent = [math]::Round((($Start / $Count) * 100))
		Set-TVGroupAssignement -devicesID $DID -groupID $NewTvgroupID -token $token
		Write-Progress -Activity "Moving in Progress" -Status "Moving: $DID" -PercentComplete $percent
		$Start += 1
	}

	if ($DeleteOldGroup -eq $true) {
		$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$header.Add("authorization", "Bearer  $token")
		Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/groups/$OldTvgroupID" -Method Delete -Headers $header -ContentType application/json
	}
}

<#
	.SYNOPSIS
		Force Assign to all Devices in a Certain group

	.DESCRIPTION
		Will only work if ownership of the devices is complete
		Some time password on device might not be correctly set and so applying policies will now work.
		Works for teamviewer 10 and up

	.PARAMETER GroupName
		Name of devices goup

	.PARAMETER PolicyName
		Name of devices Policy

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Assign-TVPolicyToAllDevicesInGroup -GroupName $value1 -PolicyName $value2

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf.
#>
function Set-TVPolicyToAllDevicesInGroup {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		$GroupName,
		[Parameter(Mandatory = $true)]
		$PolicyName,
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$TvgroupID = Get-TVGroupIDFromName -name $GroupName -token $token
	$Tvpolicy = Get-TVPolicyIdFromName -policyname $PolicyName -token $token
	$Devices = (Get-TVDevices -token $token).devices | Where-Object { $_.groupid -eq $TvgroupID }
	$Devices = $Devices.device_id
	[int]$Count = ($Devices).count
	$Start = 0
	foreach ($DID in $Devices) {

		$percent = [math]::Round((($Start / $Count) * 100))
		Set-TVPolicyAssignement -DeviceID $DID -PolicyID $Tvpolicy
		Write-Progress -Activity "Assigning Policy" -Status "Device: $DID" -PercentComplete $percent
		$Start += 1
	}
}

<#
	.SYNOPSIS
		Used To Delete Duplicate Devices Base on Alias

	.DESCRIPTION
		Will Check the most Recent Device ID has the incrementaly increase when adding new devices

	.PARAMETER Token
		A description of the Token parameter.

	.EXAMPLE
		PS C:\> Delete-TVDuplicateDevices

	.NOTES
		Additional information about the function.
#>
<#
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
}
#>

<#
	.SYNOPSIS
		Adds a Teamviewer Device
		This function supports the -WhatIf parameter

	.PARAMETER GroupID
		Teamviewer Group ID
		This is mandatory and must be passed

	.PARAMETER RemotecontrolID
		Teamviewer Device Remote Control ID

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.PARAMETER Description
		Description of the device being added

	.PARAMETER Alias
		Alias of the device being added

	.PARAMETER Password
		Teamviweer Password of the device being added

	.EXAMPLE
		PS C:\> Add-TVDevice -GroupID g41804127 -RemotecontrolID 1478523699 -Description "My Office Computer" -Alias "MY-OFF-001" -Password "Kl779d4"

	.EXAMPLE
		PS C:\> PS C:\> Add-TVDevice -GroupID g41804127 -RemotecontrolID 1478523699 -Description "My Office Computer" -Alias "MY-OFF-001" -Password "Kl779d4 -WhatIf

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Add-TVDevice {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$GroupID,
		[Parameter(Mandatory = $true)]
		[string]$RemotecontrolID,
		[string]$Token,
		[string]$Description,
		[string]$alias,
		[string]$password
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	$body = @{
		Users = @(
			@{
				remotecontrol_id = "$RemotecontrolID"
				groupid          = "$GroupID"
				description      = "$Description"
				alias            = "$alias"
				password         = "$password"
			}
		)
	} | ConvertTo-Json
	if ($PSCmdlet.ShouldProcess("$RemotecontrolID" , "Add-TVDevice")) {
		Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/devices" -Method Post -Headers $header -ContentType application/json -Body "$body"
	}
}

<#
	.SYNOPSIS
		Deletes a Teamviewer group
		This function supports the -WhatIf parameter

	.PARAMETER GroupID
		Teamviewer Group ID

	.PARAMETER token
		Is the User Level Token that you can create from the Teamviewer Management Console
		Can use Set-TVToken Function will then not be nessessary to use this paramameter

	.EXAMPLE
		PS C:\> Remove-TVGroup -GroupID g41804127

	.EXAMPLE
		PS C:\> Remove-TVGroup -GroupID g41804127 -WhatIf

	.NOTES
		For more Details see Teamviewer API token Documentation
		https://www.teamviewer.com/en/for-developers/teamviewer-api/
		https://dl.tvcdn.de/integrate/TeamViewer_API_Documentation.pdf
#>
function Remove-TVGroup {
	[CmdletBinding(ConfirmImpact = 'Medium',
		PositionalBinding = $false,
		SupportsPaging = $true,
		SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		$GroupID,
		$token
	)

	if ($global:TVToken) {
		$token = $global:TVToken
	}
	elseif ($token) {
		$token = $token
	}
	else {
		Write-Output "You need to Set the Token"
		break
	}
	$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$header.Add("authorization", "Bearer  $token")
	if ($PSCmdlet.ShouldProcess("$groupID" , "Remove-TVGroup")) {
		Invoke-RestMethod -Uri "https://webapi.teamviewer.com/api/v1/groups/$groupID" -Method Delete -Headers $header -ContentType application/json
	}
}