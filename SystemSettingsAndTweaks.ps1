##########
# 
# Windows 10/11 Settings and Tweaks - Admin Edition
# 
# Modified by: Peter
# Last updated: 2024-06-18
# 
# Heavily based on the "Win10 / WinServer2016 Initial Setup Script"
# Author: Disassembler <disassembler@dasm.cz>
# Version: v2.12, 2018-01-09
# Source: https://github.com/Disassembler0/Win10-Initial-Setup-Script
#
##########

# Relaunch the script with administrator privileges
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
	Exit
}


# Disable automatic installation of network devices
Write-Host "Disabling automatic installation of network devices..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0

# Disable Fast Startup
Write-Host "Disabling Fast Startup..."
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power")) {
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0


# Remove provisioned Microsoft applications
Write-Host "Removing provisioned Microsoft applications..."
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like "*Office.Desktop*"} | Remove-AppxProvisionedPackage -Online

# Uninstall default Microsoft applications
Write-Host "Uninstalling default Microsoft applications..."
Get-AppxPackage -allusers | Where-Object {$_.name -like "*Bing*"} | Remove-AppxPackage
Get-AppxPackage -allusers | Where-Object {$_.name -like "*Getstarted*"} | Remove-AppxPackage
Get-AppxPackage -allusers | Where-Object {$_.name -like "*Minecraft*"} | Remove-AppxPackage
Get-AppxPackage -allusers | Where-Object {$_.name -like "*OfficeHub*"} | Remove-AppxPackage
Get-AppxPackage -allusers | Where-Object {$_.name -like "*Office.Desktop*"} | Remove-AppxPackage
Get-AppxPackage -allusers | Where-Object {$_.name -like "*PowerBI*"} | Remove-AppxPackage
Get-AppxPackage -allusers | Where-Object {$_.name -like "*Skype*"} | Remove-AppxPackage
Get-AppxPackage -allusers | Where-Object {$_.name -like "*Sway*"} | Remove-AppxPackage
Get-ProvisionedAppxPackage -Online | Where-Object { $_.PackageName -like "*Solitaire*" } | ForEach-Object { Remove-ProvisionedAppxPackage -Online -PackageName $_.PackageName }
Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*Solitaire*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
Get-ProvisionedAppxPackage -Online | Where-Object { $_.PackageName -like "*xbox*" } | ForEach-Object { Remove-ProvisionedAppxPackage -Online -PackageName $_.PackageName }
Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*xbox*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }


# Disable Copilot
Write-Host "Disabling Copilot..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1

# Disable Search Highlights
Write-Host "Disabling Search Highlights..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Type DWord -Value 0

#############
# Dell tweaks
#############
# Update Dell Command | Update settings to manual only
If (Test-Path "C:\Program Files\Dell\CommandUpdate") {
	Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList '/configure -scheduleManual' -Wait
}

# Update Optimizer disable proximity sensor
If (Test-Path "C:\Program Files\Dell\DellOptimizer") {
	Start-Process "C:\Program Files\Dell\DellOptimizer\do-cli.exe" -ArgumentList '/configure -name=ProximitySensor.State -value=False' -Wait
}


#######################
# Microsoft Edge tweaks
#######################
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
}

# Prevent Edge from Importing Chrome Tabs
Write-Host "Preventing Edge from Importing Chrome Tabs..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AutoImportAtFirstRun" -Type DWord -Value 4

# Disable Sidebar
Write-Host "Disabling the Sidebar..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "HubsSidebarEnabled" -Type DWord -Value 0

# Disable Personalize your web experience in Edge
Write-Host "Disabling Personalize your web experience in Edge..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PersonalizationReportingEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "ShowRecommendationsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "EdgeEnhanceImagesEnabled" -Type DWord -Value 0

# Block recreate desktop shortcut for Edge
Write-Host "Blocking the automatic recreation of the Edge desktop shortcut..."
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\EdgeUpdate")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\EdgeUpdate" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\EdgeUpdate" -Name "CreateDesktopShortcutDefault" -Type DWord -Value 0


####################
# Wait for key press
####################
Write-Output "Tasks complete. Please restart the computer manually.\nPress any key to exit script..."
[Console]::ReadKey($true) | Out-Null
