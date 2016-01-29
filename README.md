# PowerSCCM

Functions to facilitate connections to and queries from SCCM databases for both offensive and defensive applications.

The code is kept PowerShell Version 2.0 compliant with no external dependencies.

License: BSD 3-clause

Authors: [@harmj0y](https://twitter.com/harmj0y), [@jaredcatkinson](https://twitter.com/jaredcatkinson), [@enigma0x3](https://twitter.com/enigma0x3), [@mattifestation](https://twitter.com/mattifestation)

Heavily based on [work by Brandon Helms](https://github.com/Cr0n1c/SCCM-Enumeration) that's described more [in this post](https://cr0n1c.wordpress.com/2016/01/27/using-sccm-to-violate-best-practices/).

More background information on using SCCM for DFIR is available on [@KeithTyler's](https://twitter.com/KeithTyler) blog post [on the subject](http://informationonsecurity.blogspot.com/2015/11/microsofts-accidental-enterprise-dfir.html) and in John McLeod/Mike Pilkington's ["Mining-for-Evil"](https://digital-forensics.sans.org/summit-archives/DFIR_Summit/Mining-for-Evil-John-McLeod-Mike-Pilkington.pdf) presentation.


## Usage

PowerSCCM will keep track of established SCCM database sessions, allowing you to reuse these
sessions with common queries. To establish a new session, use **New-SCCMSession** along with the 
name of the computer with the SCCM database (**-ComputerName**) and the SCCM site database name
(**-DatabaseName**):

`New-SCCMSession -ComputerName SCCM.testlab.local -DatabaseName CM_LOL`

This session is now stored in $Script:SCCMSessions and reusable by Get-SCCMSession. 

To find the available SCCM databases on a server you have access to, use **Find-SCCMDatabase**:

`Find-SCCMDatabase -ComputerName SCCM.testlab.local`

To retrieve all current SCCM session objects, us **Get-SCCMSession** with optional -Id, -Name, -ComputerName, or -DatabaseName arguments. To close and remove a session, use **Remove-SCCMSession** with any of the same arugments, or the -Session <PowerSCCM.Session> argument for a SCCM session object (passable on the pipeline).

`Get-SCCMSession | Remove-SCCMSession`


## SCCM Database/Server Functions

Various functions that deal with querying/changing information concerning the SCCM database or server, as opposed to dealing with querying inventoried client information.

### Find-SCCMDatabase
Finds the accessible SCCM databases given a MSSQL server.

### Get-SCCMApplicationCI
Returns information on user-deployed applications in an SCCM database.

### Get-SCCMPackage
Returns information on user-deployed packages in an SCCM database.

### Get-SCCMConfigurationItem
Returns SCCM configuration items in an SCCM database.

### Set-SCCMConfigurationItem
Sets a field to a particular value for a SCCM configuration keyed by CI_ID.


## Get-SCCM*

Query functions require -Session <PowerSCCM.Session> (passable on the pipeline):

`Get-SCCMSession | Get-SCCMRecentlyUsedApplication | Export-CSV -NoTypeInformation recent_apps.csv`

`Get-SCCMRecentlyUsedApplication -Session $Session | Export-CSV -NoTypeInformation recent_apps.csv`

All of these functions also share a common set of optional parameters:

* **-Newest <X>** - return only the X newest entries from the database.
* **-OrderBy <FIELD>** - order the results by a particular field.
* **-Descending** - if -OrderBy is set, display results in descending order.
* **-ComputerNameFilter <COMPUTER>** - only return results for a particular computer name.
* **-TimeStampFilter <TIMESTAMP>** - the SCCM collection timestamp to filter on, accepts <> operators.

Each function also has a set of custom -XFilter parameters that allow for query filtering on specific field names/values.


### Get-SCCMService

Returns information on the current set of running services as of the last SCCM agent query/checkin.

### Get-SCCMServiceHistory
Returns information on the historical set of running services as of the last SCCM agent query/checkin.

### Get-SCCMAutoStart
Returns information on the set of autostart programs as of the last SCCM agent query/checkin.

### Get-SCCMProcess
Returns information on the set of currently running processes as of the last SCCM agent query/checkin.

### Get-SCCMProcessHistory
Returns information on the historical set of running processes as of the last SCCM agent query/checkin.

### Get-SCCMRecentlyUsedApplication
Returns information on recently launched applications on hosts as of the last SCCM agent query/checkin.

### Get-SCCMDriver
Returns information on the set of currently laoded system drivers as of the last SCCM agent query/checkin.

### Get-SCCMConsoleUsage
Returns historical information on user console usage as of the last SCCM agent query/checkin.

### Get-SCCMSoftwareFile
Returns information on inventoried non-Microsoft software files. **This option is not enabled by default in SCCM**- we recommend setting SCCM to inventory all *.exe files on hosts.

### Get-SCCMBrowserHelperObject
Returns information on discovered browser helper objects. **This option is not enabled by default in SCCM**.

### Get-SCCMShare
Returns information on discovered shares.**This option is not enabled by default in SCCM**.

### Get-SCCMPrimaryUser
Returns user/machine pairings where the user is set as a 'Primary User' through SCCM.


## Find-SCCM*

Meta-functions that use the Get-SCCM* query functions to find common 'bad' things. All of these functions -Session <PowerSCCM.Session> (passable on the pipeline).

### Find-SCCMRenamedCMD
Finds renamed cmd.exe executables using Get-SCCMRecentlyUsedApplication and appropriate filters.

### Find-SCCMUnusualEXE
Finds recently launched applications that don't end in *.exe using Get-SCCMRecentlyUsedApplication and appropriate filters.

### Find-SCCMRareApplication
Finds the rarest -Limit <X> recently launched applications that don't end in *.exe using Get-SCCMRecentlyUsedApplication and appropriate filters.

### Find-SCCMPostExploitation
Finds recently launched applications commonly used in post-exploitation.

### Find-SCCMPostExploitationFile
Finds indexed .exe's commonly used in post-exploitation.

### Find-SCCMMimikatz
Finds launched mimikatz instances by searching the 'FileDescription' and 'CompanyName' fields of recently launched applications.

### Find-SCCMMimikatzFile
Finds inventoried mimikatz.exe instances by searching the 'FileDescription' field of inventoried .exe's.
