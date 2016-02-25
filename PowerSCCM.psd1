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
    'New-SccmSession',
    'Get-SccmSession',
    'Remove-SccmSession',
    'Find-SccmSiteCode',
    'Get-SccmApplication',
    'Get-SccmPackage',
    'Get-SccmConfigurationItem',
    'Set-SccmConfigurationItem',
    'Get-SccmCollection',
    'Get-SccmCollectionMember',
    'Get-SccmService',
    'Get-SccmServiceHistory',
    'Get-SccmAutoStart',
    'Get-SccmProcess',
    'Get-SccmProcessHistory',
    'Get-SccmRecentlyUsedApplication',
    'Get-SccmDriver',
    'Get-SccmConsoleUsage',
    'Get-SccmSoftwareFile',
    'Get-SccmBrowserHelperObject',
    'Get-SccmShare',
    'Get-SccmPrimaryUser',
    'Find-SccmRenamedCMD',
    'Find-SccmUnusualEXE',
    'Find-SccmRareApplication',
    'Find-SccmPostExploitation',
    'Find-SccmPostExploitationFile',
    'Find-SccmMimikatz',
    'Find-SccmMimikatzFile',
    'Get-SccmADForest',
    'Get-SccmComputer',
    'New-SccmCollection',
    'Remove-SccmCollection',
    'Add-SccmDeviceToCollection',
    'Add-SccmUserToCollection',
    'New-SccmApplication',
    'Invoke-SCCMDeviceCheckin',
    'Remove-SccmApplication',
    'New-SccmApplicationDeployment',
    'Remove-SccmApplicationDeployment',
    'Push-WmiPayload',
    'Remove-WmiPayload',
    'Grant-WmiNameSpaceRead ',
    'Revoke-WmiNameSpaceRead'
)

# List of all files packaged with this module
FileList = @('PowerSCCM.psm1', 'PowerSCCM.psd1', 'PowerSCCM.ps1')

}
