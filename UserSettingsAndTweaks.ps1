##########
# 
# Windows 10/11 Settings and Tweaks - User Edition
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



##########
# Privacy Settings
##########

# Disable Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0

# Checking for ContentDeliveryManager key
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null
}

# Disables app suggestions
Write-Output "Disabling Application suggestions..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0

# Disable Suggestions in the timeline
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0

# Disable Suggestions in the Start menu
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0

# Disable App Launch Tracking
Write-Output "Disabling App Launch Tracking..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0

# Disable Windows Welcome Experience
Write-Output "Disabling Windows Welcome Experience..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0

# Disable Website Access to Language List
Write-Output "Disabling Website Access to Language List..."
If (!(Test-Path "HKCU:\Control Panel\International\User Profile")) {
	New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1

# Check for Explorer\Advanced key
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
}

# Disable App Launch Tracking
Write-Output "Disabling App Launch Tracking..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 0

# Disable Start Menu Ads
Write-Output "Disabling Start Menu Advertising..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Type DWord -Value 0

# Disable File Explorer Ads
Write-Output "Disabling File Explorer Ads..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Type DWord -Value 0

# Disable Windows Copilot button (Win11)
Write-Output "Disabling Windows Copilot (user level)..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Type DWord -Value 0

# Disable User Profile Engagement
# aka Get even more out of Windows
# aka Let's make Windows even better
Write-Output "Disabling User Profile Engagement..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0

# Disable Search Highlights
Write-Output "Disabling Search Highlights..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDynamicSearchBoxEnabled" -Type DWord -Value 0

# Disable Microsoft Account search
Write-Output "Disabling Microsoft Account search..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsMSACloudSearchEnabled" -Type DWord -Value 0

# Disable Work or School Account search
Write-Output "Disabling Work or School Account search..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsAADCloudSearchEnabled" -Type DWord -Value 0

# Disable Windows Copilot
Write-Output "Disabling Windows Copilot (user level)..."
If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot")) {
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1


##########
# Edge Browser Settings
##########

# Disable 
# Write-Output "Disabling Windows Copilot (user level)..."
# If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
# 	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
# }
# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Type DWord -Value 0

# Set Microsoft Edge to not show first run experience
Write-Host "Hiding the Edge browser first run experience..."
If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge")) {
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Type DWord -Value 1


##########
# Accessibility Settings
##########

# Disable Sticky keys prompt
Write-Output "Disabling Sticky keys prompt..."
If (!(Test-Path "HKCU:\Control Panel\Accessibility\StickyKeys")) {
	New-Item -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"


##########
# Windows UI Tweaks
##########

# Hide Task View button
Write-Output "Hiding Task View button..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0


# Hide Taskbar People icon
Write-Output "Hiding People icon..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

# Disable Snap Assist
Write-Output "Disabling Snap Assist..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SnapAssist" -Type DWord -Value 0

# Disable Meet Now
Write-Output "Disabling Meet Now..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1

# Disable Cortana button
Write-Output "Disabling Cortana button..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0

# Disable News & Interests "Open on hover" feature
Write-Output "Disabling News Open on Hover feature..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarOpenOnHover" -Type DWord -Value 0


##########
# Windows File Manager Settings
##########

# Show known file extensions
Write-Output "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

# Change default Explorer view to This PC
Write-Output "Changing default Explorer view to This PC..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1


##########
# Office registry tweaks
##########

# Disables Protected view for Excel 2016 desktop applications
Write-Output "Disabling Protected view for Office desktop applications..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security\ProtectedView")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableInternetFilesInPV" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableAttachmentsInPV" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableUnsafeLocationsInPV" -Type DWord -Value 1

# Disables Protected view for Word 2016 desktop applications
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security\ProtectedView")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security\ProtectedView" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security\ProtectedView" -Name "DisableInternetFilesInPV" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security\ProtectedView" -Name "DisableAttachmentsInPV" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security\ProtectedView" -Name "DisableUnsafeLocationsInPV" -Type DWord -Value 1

# Disables Protected view for PowerPoint 2016 desktop applications
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security\ProtectedView")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security\ProtectedView" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security\ProtectedView" -Name "DisableInternetFilesInPV" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security\ProtectedView" -Name "DisableAttachmentsInPV" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security\ProtectedView" -Name "DisableUnsafeLocationsInPV" -Type DWord -Value 1

# Allows network locations for Excel 2016 desktop applications
Write-Output "Allowing network locations for Office desktop applications..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security\Trusted Locations")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security\Trusted Locations" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security\Trusted Locations" -Name "AllowNetworkLocations" -Type DWord -Value 1

# Allows network locations for Word 2016 desktop applications
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Locations" -Name "AllowNetworkLocations" -Type DWord -Value 1

# Allows network locations for PowerPoint 2016 desktop applications
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security\Trusted Locations")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security\Trusted Locations" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security\Trusted Locations" -Name "AllowNetworkLocations" -Type DWord -Value 1

# Increases max size for Outlook 2016 OST/PST files
Write-Output "Increasing max size for Outlook OST/PST files..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\PST")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\PST" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\PST" -Name "MaxLargeFileSize" -Type DWord -Value 0x00019000
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\PST" -Name "WarnLargeFileSize" -Type DWord -Value 0x00017c00
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\PST" -Name "MaxFileSize" -Type DWord -Value 0x7bb04400
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\PST" -Name "WarnFileSize" -Type DWord -Value 0x74404400


##########
# Specific AppxPackage Removals
##########

# Uninstall default UWP applications
Write-Output "Uninstalling default Microsoft applications..."
Get-AppxPackage | Where-Object {$_.name -like "*Bing*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*Xbox*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*Getstarted*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*Minecraft*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*OfficeHub*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*Office.Desktop*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*Skype*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*Solitaire*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*Partner*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*MicrosoftTeams*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*Outlook*"} | Remove-AppxPackage
Get-AppxPackage | Where-Object {$_.name -like "*windowscommunicationsapps*"} | Remove-AppxPackage


##########
# Auxiliary Functions
##########

# Wait for key press
Write-Output "Tasks complete. Press any key to exit script..."
[Console]::ReadKey($true) | Out-Null
