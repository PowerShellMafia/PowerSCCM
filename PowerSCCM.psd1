@{

# Script module or binary module file associated with this manifest
ModuleToProcess = 'PowerSCCM.psm1'

# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = '0ac82760-3e0d-4124-bd1c-92c8dab97171'

# Author of this module
Author = '@harmj0y', '@jaredcatkinson', '@enigma0x3', '@mattifestation'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerShell module to interact with SCCM databases'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = @(
    'New-SCCMSession',
    'Get-SCCMSession',
    'Remove-SCCMSession',
    'Find-SCCMDatabase',
    'Get-SCCMApplicationCI',
    'Get-SCCMPackage',
    'Get-SCCMConfigurationItem',
    'Set-SCCMConfigurationItem',
    'Get-SCCMCollection',
    'Get-SCCMCollectionMember',
    'Get-SCCMService',
    'Get-SCCMServiceHistory',
    'Get-SCCMAutoStart',
    'Get-SCCMProcess',
    'Get-SCCMProcessHistory',
    'Get-SCCMRecentlyUsedApplication',
    'Get-SCCMDriver',
    'Get-SCCMConsoleUsage',
    'Get-SCCMSoftwareFile',
    'Get-SCCMBrowserHelperObject',
    'Get-SCCMShare',
    'Get-SCCMPrimaryUser',
    'Find-SCCMRenamedCMD',
    'Find-SCCMUnusualEXE',
    'Find-SCCMRareApplication',
    'Find-SCCMPostExploitation',
    'Find-SCCMPostExploitationFile',
    'Find-SCCMMimikatz',
    'Find-SCCMMimikatzFile',
    'Get-SCCMADForest',
    'Get-SCCMADUser',
    'Get-SCCMADGroup',
    'Get-SCCMADGroupMember'
)

# List of all files packaged with this module
FileList = @('PowerSCCM.psm1', 'PowerSCCM.psd1', 'PowerSCCM.ps1')

}
