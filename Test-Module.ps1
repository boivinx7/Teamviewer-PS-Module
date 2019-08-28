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
#Create-TVUser -UserEmail "maxime.bilodeau-boivin@agropur.com" -defaultUserPermissions EditFullProfile -defaultUserPassword "Agropur01" -DefaultUserLanguage en -UserFullName "Maxime BB"
#Get-TVUsers | Where-Object {$_.name -like "*bassem*"}

#Remove-TVUser -UserID ""
get-tvgroups