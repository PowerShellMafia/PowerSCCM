# PowerSCCM

### Warning: This code is alpha and minimally tested!

Functions to facilitate connections to and queries from SCCM databases and WMI interfaces for both offensive and defensive applications.

The code is kept PowerShell Version 2.0 compliant with no external dependencies.

License: BSD 3-clause

Authors: [@harmj0y](https://twitter.com/harmj0y), [@jaredcatkinson](https://twitter.com/jaredcatkinson), [@enigma0x3](https://twitter.com/enigma0x3), [@mattifestation](https://twitter.com/mattifestation)

Heavily based on [work by Brandon Helms](https://github.com/Cr0n1c/SCCM-Enumeration) that's described more [in this post](https://cr0n1c.wordpress.com/2016/01/27/using-Sccm-to-violate-best-practices/), as well as [SCCM POSH](http://www.snowland.se/powershell/sccm-posh/) by Rikard Rönnkvist.

More background information on using SCCM for DFIR is available on [@KeithTyler's](https://twitter.com/KeithTyler) blog post [on the subject](http://informationonsecurity.blogspot.com/2015/11/microsofts-accidental-enterprise-dfir.html) and in John McLeod/Mike Pilkington's ["Mining-for-Evil"](https://digital-forensics.sans.org/summit-archives/DFIR_Summit/Mining-for-Evil-John-McLeod-Mike-Pilkington.pdf) presentation.


## Usage

PowerSCCM will keep track of established SCCM database/WMI sessions, allowing you to reuse these
sessions with common queries. To establish a new session, use **New-SccmSession** along with the 
name of the computer with the SCCM database (**-ComputerName**) and the SCCM site database name
(**-DatabaseName**):

`New-SccmSession -ComputerName SCCM.testlab.local -DatabaseName CM_LOL`

This session is now stored in $Script:SCCMSessions and reusable by Get-SccmSession. To establish a session via WMI, use **-ConnectionType WMI**.

To find the available SCCM site codes on a server you have access to, use **Find-SccmSiteCode**:

`Find-SccmSiteCode -ComputerName SCCM.testlab.local`

To retrieve all current SCCM session objects, us **Get-SccmSession** with optional -Id, -Name, -ComputerName, -SiteCode, or -ConnectionType arguments. To close and remove a session, use **Remove-SccmSession** with any of the same arugments, or the -Session <PowerSCCM.Session> argument for a SCCM session object (passable on the pipeline).

`Get-SccmSession | Remove-SccmSession`

See the bottom of this README.md for offensive deployment.


## SCCM Database/Server Functions

Various functions that deal with querying/changing information concerning the SCCM database or server, as opposed to dealing with querying inventoried client information.

#### Find-LocalSccmInfo
Finds the site code and management point for a local system.

#### Find-SccmSiteCode
Finds SCCM site codes for a given server.

#### Get-SccmApplication
Returns information on user-deployed applications in an SCCM database.

#### Get-SccmPackage
Returns information on user-deployed packages in an SCCM database.

#### Get-SccmConfigurationItem
Returns SCCM configuration items in an SCCM database.

#### Set-SccmConfigurationItem
Sets a field to a particular value for a SCCM configuration keyed by CI_ID.

#### Get-SccmCollection
Returns SCCM collections that exist on the primary site server.

#### Get-SccmCollectionMember
Returns SCCM collection members.

## Get-Sccm*

Query functions require -Session <PowerSCCM.Session> (passable on the pipeline):

`Get-SccmSession | Get-SccmRecentlyUsedApplication | Export-CSV -NoTypeInformation recent_apps.csv`

`Get-SccmRecentlyUsedApplication -Session $Session | Export-CSV -NoTypeInformation recent_apps.csv`

All of these functions also share a common set of optional parameters:

* **-Newest <X>** - return only the X newest entries from the database.
* **-OrderBy <FIELD>** - order the results by a particular field.
* **-Descending** - if -OrderBy is set, display results in descending order.
* **-ComputerNameFilter <COMPUTER>** - only return results for a particular computer name.
* **-TimeStampFilter <TIMESTAMP>** - the SCCM collection timestamp to filter on, accepts <> operators.

Each function also has a set of custom -XFilter parameters that allow for query filtering on specific field names/values.


#### Get-SccmService
Returns information on the current set of running services as of the last SCCM agent query/checkin.

#### Get-SccmServiceHistory
Returns information on the historical set of running services as of the last SCCM agent query/checkin.

#### Get-SccmAutoStart
Returns information on the set of autostart programs as of the last SCCM agent query/checkin.

#### Get-SccmProcess
Returns information on the set of currently running processes as of the last SCCM agent query/checkin.

#### Get-SccmProcessHistory
Returns information on the historical set of running processes as of the last SCCM agent query/checkin.

#### Get-SccmRecentlyUsedApplication
Returns information on recently launched applications on hosts as of the last SCCM agent query/checkin.

#### Get-SccmDriver
Returns information on the set of currently laoded system drivers as of the last SCCM agent query/checkin.

#### Get-SccmConsoleUsage
Returns historical information on user console usage as of the last SCCM agent query/checkin.

#### Get-SccmSoftwareFile
Returns information on inventoried non-Microsoft software files. **This option is not enabled by default in SCCM**- we recommend setting SCCM to inventory all *.exe files on hosts.

#### Get-SccmBrowserHelperObject
Returns information on discovered browser helper objects. **This option is not enabled by default in SCCM**.

#### Get-SccmShare
Returns information on discovered shares.**This option is not enabled by default in SCCM**.

#### Get-SccmPrimaryUser
Returns user/machine pairings where the user is set as a 'Primary User' through SCCM.


## Find-Sccm*

Meta-functions that use the Get-Sccm* query functions to find common 'bad' things. All of these functions -Session <PowerSCCM.Session> (passable on the pipeline).

#### Find-SccmRenamedCMD
Finds renamed cmd.exe executables using Get-SccmRecentlyUsedApplication and appropriate filters.

#### Find-SccmUnusualEXE
Finds recently launched applications that don't end in *.exe using Get-SccmRecentlyUsedApplication and appropriate filters.

#### Find-SccmRareApplication
Finds the rarest -Limit <X> recently launched applications that don't end in *.exe using Get-SccmRecentlyUsedApplication and appropriate filters.

#### Find-SccmPostExploitation
Finds recently launched applications commonly used in post-exploitation.

#### Find-SccmPostExploitationFile
Finds indexed .exe's commonly used in post-exploitation.

#### Find-SccmMimikatz
Finds launched mimikatz instances by searching the 'FileDescription' and 'CompanyName' fields of recently launched applications.

#### Find-SccmMimikatzFile
Finds inventoried mimikatz.exe instances by searching the 'FileDescription' field of inventoried .exe's.


## SCCM Active Directory Functions

#### Get-SccmADForest
Returns information on Active Directory forests enumerated by SCCM agents.

#### Get-SccmComputer
Returns information on Active Directory computers.


## Offensive Functions

#### New-SccmCollection
Create a SCCM collection to place target computers/users in for application deployment.

#### Remove-SccmCollection
Deletes a SCCM collection.

#### Add-SccmDeviceToCollection
Add a computer to a device collection for application deployment

#### Add-SccmUserToCollection
Add a domain user to a user collection for application deployment.

#### New-SccmApplication
Creates a new SCCM application.

#### Remove-SccmApplication
Deletes a SCCM application.

#### New-SccmApplicationDeployment
Deploys an application to a specific collection.

#### Invoke-SCCMDeviceCheckin
Forces all members of a collection to immediately check for Machine policy updates and execute any new applications.

#### Remove-SccmApplicationDeployment
Deletes a SCCM application deployment.

#### Push-WmiPayload
Pushes a payload to a custom WMI class on a remote server.

#### Remove-WmiPayload
Removes a saved WMI payload pushed by Push-WmiPayload.

#### Grant-WmiNameSpaceRead 
Grants remote read access to 'Everyone' for a given WMI namespace.

#### Revoke-WmiNameSpaceRead
Removes remote read access from 'Everyone' for a given WMI namespace that was granted by Grant-WmiNameSpaceRead.

#### New-CMScriptDeployement
Permits to deploy a PowerShell script (called a CMScript) on a distant machine with SCCM, instead of an application.

## Offensive Deployment

It takes a few steps to deploy malicious packages/scripts to clients through SCCM, and offensive manipulation/deployment is only currently supported through WMI SCCM sessions. SCCM deployments need three parts- a user/device collection of targets, a malicious application to deploy, and a deployment that binds the two together. 

To create a collection to place targets in, use **New-SccmCollection**, along with the -CollectionName and -CollectionType ('Device' or 'User') parameters. You then need to add targets to the collection, either with **Add-SccmDeviceToCollection** or **Add-SccmUserToCollection** depending on the collection type.

Once the target collection is completed, create a new malicious application with **New-SccmApplication**. You need to specify an -ApplicationName, and then can choose to deploy a -UNCProgram (for a hosted binary payload), -PowerShellScript (for the text of a PowerShell script to deploy), -PowerShellB64 (for an ASCII base64-encoded PowerShell blob), or -PowerShellUnicodeB64 (for an UNICODE base64-encoded PowerShell blob). The targeted payload will be created and pushed to a custom WMI class on the SCCM server using Push-WmiPayload, universal read permissions will be granted with Grant-WmiNameSpaceRead, and the application will be created and marked as 'Hidden' in the main SCCM GUI.

Finally, you can deploy a newly created application to a given collection with **New-SccmApplicationDeployment**, specifying the -ApplicationName and -CollectionName respectively, as well as a -AssignmentName to name the deployment. Once the SCCM agents check back in your malicious application should deploy.

## Offensive Cleanup

Cleanup functions exist for all offensive actions.

To remove an application deployment, use **Remove-SccmApplicationDeployment**.

To enumerate the current collections use Get-SccmCollection, and to remove a collection created by New-SccmCollection, use **Remove-SccmCollection**.

To enumerate the current applications use Get-SccmApplication, and to remove a collection created by New-SccmApplication, use **Remove-SccmApplication**. This also calls **Remove-WmiPayload** to remove the pushed WMI payload, and to revokes the namespace read with **Revoke-WmiNameSpaceRead**.
