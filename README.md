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


## SCCM Database/Server Functions

Various functions that deal with querying/changing information concerning the SCCM database or server, as opposed to dealing with querying inventoried client information.

### Find-SccmSiteCode
Finds SCCM site codes for a given server.

### Get-SccmApplicationCI
Returns information on user-deployed applications in an SCCM database.

### Get-SccmPackage
Returns information on user-deployed packages in an SCCM database.

### Get-SccmConfigurationItem
Returns SCCM configuration items in an SCCM database.

### Set-SccmConfigurationItem
Sets a field to a particular value for a SCCM configuration keyed by CI_ID.

### Get-SccmCollection
Returns SCCM collections that exist on the primary site server.

### Get-SccmCollectionMember
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


### Get-SccmService

Returns information on the current set of running services as of the last SCCM agent query/checkin.

### Get-SccmServiceHistory
Returns information on the historical set of running services as of the last SCCM agent query/checkin.

### Get-SccmAutoStart
Returns information on the set of autostart programs as of the last SCCM agent query/checkin.

### Get-SccmProcess
Returns information on the set of currently running processes as of the last SCCM agent query/checkin.

### Get-SccmProcessHistory
Returns information on the historical set of running processes as of the last SCCM agent query/checkin.

### Get-SccmRecentlyUsedApplication
Returns information on recently launched applications on hosts as of the last SCCM agent query/checkin.

### Get-SccmDriver
Returns information on the set of currently laoded system drivers as of the last SCCM agent query/checkin.

### Get-SccmConsoleUsage
Returns historical information on user console usage as of the last SCCM agent query/checkin.

### Get-SccmSoftwareFile
Returns information on inventoried non-Microsoft software files. **This option is not enabled by default in SCCM**- we recommend setting SCCM to inventory all *.exe files on hosts.

### Get-SccmBrowserHelperObject
Returns information on discovered browser helper objects. **This option is not enabled by default in SCCM**.

### Get-SccmShare
Returns information on discovered shares.**This option is not enabled by default in SCCM**.

### Get-SccmPrimaryUser
Returns user/machine pairings where the user is set as a 'Primary User' through SCCM.


## Find-Sccm*

Meta-functions that use the Get-Sccm* query functions to find common 'bad' things. All of these functions -Session <PowerSCCM.Session> (passable on the pipeline).

### Find-SccmRenamedCMD
Finds renamed cmd.exe executables using Get-SccmRecentlyUsedApplication and appropriate filters.

### Find-SccmUnusualEXE
Finds recently launched applications that don't end in *.exe using Get-SccmRecentlyUsedApplication and appropriate filters.

### Find-SccmRareApplication
Finds the rarest -Limit <X> recently launched applications that don't end in *.exe using Get-SccmRecentlyUsedApplication and appropriate filters.

### Find-SccmPostExploitation
Finds recently launched applications commonly used in post-exploitation.

### Find-SccmPostExploitationFile
Finds indexed .exe's commonly used in post-exploitation.

### Find-SccmMimikatz
Finds launched mimikatz instances by searching the 'FileDescription' and 'CompanyName' fields of recently launched applications.

### Find-SccmMimikatzFile
Finds inventoried mimikatz.exe instances by searching the 'FileDescription' field of inventoried .exe's.


## SCCM Active Directory Functions

### Get-SccmADForest
Returns information on Active Directory forests enumerated by SCCM agents.

### Get-SccmADUser
Returns information on Active Directory users enumerated by SCCM agents.

### Get-SccmADGroup
Returns information on Active Directory group enumerated by SCCM agents.

### Get-SccmADGroupMember
Returns information on Active Directory group membership enumerated by SCCM agents
