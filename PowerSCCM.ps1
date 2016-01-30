#requires -version 2


# global store for established SCCM connection objects
[System.Collections.ArrayList]$Script:SCCMSessions = @()
$Script:SCCMSessionCounter = 0


# make sure sessions are killed on powershell.exe exit
$Null = Register-EngineEvent -SourceIdentifier ([Management.Automation.PsEngineEvent]::Exiting) -Action {
        Write-Warning 'Cleaning up any existing SCCM connections!'
        Get-SCCMSession | Remove-SCCMSession
}


function New-SCCMSession {
<#
    .SYNOPSIS

        Initiates a new SCCM database connection, returning a custom PowerSCCM.Session
        object that stores a unique Id and Name, as well as the ComputerName and 
        DatabaseName used for the connection, and the [System.Data.SQLClient.SQLConnection]
        object used for future queries of the specified database. Also stores the
        PowerSCCM.Session object in the $Script:SCCMSessions array for later access by
        Get-SCCMSession.

    .PARAMETER ComputerName

        The hostname of the SCCM database server.

    .PARAMETER DatabaseName

        The name of the database on the SCCM server.

    .PARAMETER Credential

        A [Management.Automation.PSCredential] object that stores a SqlUserName and SqlPassword.

    .PARAMETER SqlUserName

        Specific MSSQL username to use instead of integrated Windows authentication.

    .PARAMETER SqlPassword

        Specific MSSQL username to use instead of integrated Windows authentication.

    .EXAMPLE

        PS C:\> New-SCCMSession -ComputerName SCCMServer -DatabaseName CM_LOL
    
        Connect to the CM_LOL database on SCCMServer using integrated Windows authentication
        and store the connection object.

    .EXAMPLE

        PS C:\> New-SCCMSession -ComputerName SCCM -DatabaseName CM_LOL -SqlUserName sqladmin -SqlPassword 'Password123!'

        Connect to the CM_LOL database on SCCMServer using explicit MSSQL credentials
        and store the connection object.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerName,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DatabaseName,

        [Parameter(ParameterSetName = 'PSCredential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory=$True, ParameterSetName = 'SQLCredentials')]
        [String]
        [ValidateNotNullOrEmpty()]
        $SqlUserName,

        [Parameter(Mandatory=$True, ParameterSetName = 'SQLCredentials')]
        [String]
        [ValidateNotNullOrEmpty()]
        $SqlPassword
    )

    try {
        $SQLConnection = New-Object System.Data.SQLClient.SQLConnection

        Write-Verbose "Connecting to SCCM server\database $ComputerName\$DatabaseName"

        if($PSBoundParameters['Credential']) {
            $SqlUserName = $Credential.UserName
            $SqlPassword = $Credential.GetNetworkCredential().Password
            Write-Verbose "Connecting using MSSQL credentials: '$SqlUserName : $SqlPassword'"
            $SQLConnection.ConnectionString ="Server=$ComputerName;Database=$DatabaseName;User Id=$SqlUserName;Password=$SqlPassword;Trusted_Connection=True;"
            Write-Verbose "Connection string: $($SQLConnection.ConnectionString)"
        }
        elseif($PSBoundParameters['SqlUserName']) {
            Write-Verbose "Connecting using MSSQL credentials: '$SqlUserName : $SqlPassword'"
            $SQLConnection.ConnectionString ="Server=$ComputerName;Database=$DatabaseName;User Id=$SqlUserName;Password=$SqlPassword;Trusted_Connection=True;"
            Write-Verbose "Connection string: $($SQLConnection.ConnectionString)"
        }
        else {
            Write-Verbose "Connecting using integrated Windows authentication"
            $SQLConnection.ConnectionString ="Server=$ComputerName;Database=$DatabaseName;Integrated Security=True;"
            Write-Verbose "Connection string: $($SQLConnection.ConnectionString)"
        }
        
        $SQLConnection.Open()

        $Script:SCCMSessionCounter += 1

        $SCCMSessionObject = New-Object PSObject
        $SCCMSessionObject | Add-Member Noteproperty 'Id' $Script:SCCMSessionCounter
        $SCCMSessionObject | Add-Member Noteproperty 'Name' $($DatabaseName + $Script:SCCMSessionCounter)
        $SCCMSessionObject | Add-Member Noteproperty 'ComputerName' $ComputerName
        $SCCMSessionObject | Add-Member Noteproperty 'DatabaseName' $DatabaseName
        $SCCMSessionObject | Add-Member Noteproperty 'SCCMVersion' $Null
        $SCCMSessionObject | Add-Member Noteproperty 'Permissions' $Null
        $SCCMSessionObject | Add-Member Noteproperty 'SqlConnection' $SQLConnection
        
        # add in our custom object type
        $SCCMSessionObject.PSObject.TypeNames.Add('PowerSCCM.Session')
        
        # get the SCCM version used
        $SCCMVersionQuery = "SELECT TOP 1 LEFT(Client_Version0,CHARINDEX('.',Client_Version0)-1) as SCCM_Version FROM v_R_System"
        $SCCMVersion = (Invoke-SQLQuery -Session $SCCMSessionObject -Query $SCCMVersionQuery).SCCM_Version
        $SCCMSessionObject.SCCMVersion = $SCCMVersion

        # get the current user database permissions
        $PermissionsQuery = "SELECT permission_name FROM fn_my_permissions (NULL, 'DATABASE')"
        $Permissions = Invoke-SQLQuery -Session $SCCMSessionObject -Query $PermissionsQuery | ForEach-Object { $_.permission_name }
        $SCCMSessionObject.Permissions = $Permissions

        if(!($Permissions -contains "SELECT")) {
            Write-Warning "Current user does not have SELECT permissions!"
        }
        if(!($Permissions -contains "UPDATE")) {
            Write-Warning "Current user does not have UPDATE permissions!"
        }

        # return the new session object to the pipeline        
        $SCCMSessionObject

        # store the session object in the script store
        $Null = $Script:SCCMSessions.add($SCCMSessionObject)
    }
    catch {
        Write-Error "[!] Error connecting to $ComputerName\$DatabaseName : $_"
    }
}


function Get-SCCMSession {
<#
    .SYNOPSIS

        Returns a stored database connection (keyed by DatabaseName) or all
        stored database connections (the default).

    .PARAMETER Id

        The Id of a stored SCCM session object created by New-SCCMSession.

    .PARAMETER Name

        The Name of a stored SCCM session object created by New-SCCMSession,
        wildcards accepted.

    .PARAMETER ComputerName

        The ComputerName of a stored SCCM session object created by New-SCCMSession,
        wildcards accepted.

    .PARAMETER DatabaseName

        The DatabaseName of a stored SCCM session object created by New-SCCMSession,
        wildcards accepted.

    .EXAMPLE

        PS C:\> Get-SCCMSession

        Return all active SCCM database sessions stored.

    .EXAMPLE

        PS C:\> Get-SCCMSession -Id 3

        Return the active database sessions stored for Id of 3

    .EXAMPLE

        PS C:\> Get-SCCMSession -Name CM_LOL1

        Return named CM_LOL1 active database session

    .EXAMPLE

        PS C:\> Get-SCCMSession -ComputerName SCCMSERVER

        Return the active database sessions stored for the SCCMSERVER machine

    .EXAMPLE

        PS C:\> Get-SCCMSession -DatabaseName CM_LOL

        Return the active database sessions stored for CM_LOL.
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Int]
        $Id,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DatabaseName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerName
    )

    if($PSBoundParameters['Session']) {
        $Session
    }

    elseif($Script:SCCMSessions) {

        if($PSBoundParameters['Id']) {
            $Script:SCCMSessions.Clone() | Where-Object {
                $_.Id -eq $Id
            }
        }

        elseif($PSBoundParameters['Name']) {
            $Script:SCCMSessions.Clone() | Where-Object {
                $_.Name -like $Name
            }
        }

        elseif($PSBoundParameters['ComputerName']) {
            if($PSBoundParameters['DatabaseName']) {
                $Script:SCCMSessions.Clone() | Where-Object {
                    ($_.ComputerName -like $ComputerName) -and ($_.DatabaseName -like $DatabaseName)
                }
            }
            else {
                $Script:SCCMSessions.Clone() | Where-Object {
                    $_.ComputerName -like $ComputerName
                }
            }
        }

        elseif($PSBoundParameters['DatabaseName']) {
            $Script:SCCMSessions.Clone() | Where-Object {
                $_.DatabaseName -like $DatabaseName
            }
        }

        else {
            $Script:SCCMSessions.Clone()
        }
    }
}


function Remove-SCCMSession {
<#
    .SYNOPSIS

        Closes and destroys a SCCM database connection object either passed
        on the pipeline or specified by -DatabaseName.

    .PARAMETER Session

        The custom PowerSCCM.Session object generated and stored by New-SCCMSession,
        passable on the pipeline.

    .PARAMETER Id

        The Id of a stored SCCM session object created by New-SCCMSession.

    .PARAMETER Name

        The Name of a stored SCCM session object created by New-SCCMSession,
        wildcards accepted.

    .PARAMETER ComputerName

        The ComputerName of a stored SCCM session object created by New-SCCMSession,
        wildcards accepted.

    .PARAMETER DatabaseName

        The DatabaseName of a stored SCCM session object created by New-SCCMSession,
        wildcards accepted.

    .EXAMPLE

        PS C:\> Remove-SCCMSession -Id 3

        Destroy/remove the active database sessions stored for Id of 3

    .EXAMPLE

        PS C:\> Remove-SCCMSession -Name CM_LOL1

        Destroy/remove the named CM_LOL1 active database session

    .EXAMPLE

        PS C:\> Remove-SCCMSession -ComputerName SCCMSERVER

        Destroy/remove the active database sessions stored for the SCCMSERVER machine

    .EXAMPLE

        PS C:\> Remove-SCCMSession -DatabaseName CM_LOL

        Destroy/remove the active database sessions stored for CM_LOL.

    .EXAMPLE

        PS C:\> Get-SCCMSession -Name CM_LOL1 | Remove-SCCMSession

        Close/destroy the active database session stored for the CM_LOL1 named session.
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Int]
        $Id,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DatabaseName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerName
    )

    process {
        Get-SCCMSession @PSBoundParameters | ForEach-Object {
            Write-Verbose "Removing session '$($_.Name)'"
            $_.SqlConnection.Close()
            $Script:SCCMSessions.Remove($_)
        }
    }
}


function Invoke-SQLQuery {
<#
    .SYNOPSIS

        Helper that executes a given SCCM SQL query on the passed, specified, or
        current (default) SCCM database session connection.
        Should not normally be called by the user.

    .PARAMETER Session

        The custom PowerSCCM.Session object returned by Get-SCCMSession, passable on the pipeline.

    .PARAMETER Query

        The SCCM SQL query to run.
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $Query
    )

    process {

        if($Query.Trim().StartsWith("-- MIN_SCCM_VERSION")) {
            # if the query specifies a minimum version, make sure this connection complies
            $FirstLine = $($Query -Split "\n")[0]
            $MinVersion = ($FirstLine -Split "=")[1].trim()

            if($MinVersion) {
                if($MinVersion -gt $($Session.SCCMVersion)) {
                    Throw "Query requires a minimum SCCM version ($MinVersion) higher than the current connection ($($Session.SCCMVersion))!"
                }
            }
        }

        Write-Verbose "Running query on session $($Session.Name): $Query"

        $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($Query, $Session.SqlConnection)

        $Table = New-Object System.Data.DataSet
        $Null = $SqlAdapter.Fill($Table)

        $Table.Tables[0]
    }
}


function Get-FilterQuery {
<#
    .SYNOPSIS

        Helper that takes a -Query string and a set of PSBoundParameters
        and returns the appropriate final query string for a Get-SCCM*
        function based on the given filter options.

    .PARAMETER Query

        The multi-line SQL query string to append logic to.

    .PARAMETER Parameters

        The passed $PSBoundParameter set.
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory=$True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Query,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        $Parameters
    )

    if($Parameters['Filter']) {
        # if a single hard -Filter <X> is set, ignore other filter parameters
        $Filter = $Filter.Replace('*', '%')

        if($Query.EndsWith("AS DATA")) {
            $Query += "`nWHERE ($Filter)"
        }
        else {
            $Query += "`nAND ($Filter)"
        }
    }
    else {

        $Parameters.GetEnumerator() | Where-Object {($_.Key -like '*Filter') -and ($_.Key -ne 'Filter')} | ForEach-Object {

            # get the SQL wildcards correct
            $Value = $_.Value.Replace('*', '%')

            # if we have multiple values to build clauses for
            if($Value.contains(" or ")){
                $Values = $Value -split " or " | ForEach-Object {$_.trim()}
            }
            else {
                $Values = @($Value)
            }

            if($Query.EndsWith("AS DATA")) {
                $Query += "`nWHERE ("
            }
            else {
                $Query += "`nAND ("
            }
            $Clauses = @()

            ForEach ($Value in $Values) {

                if($Value.StartsWith('!')) {
                    $Operator = "NOT LIKE"
                    $Value = $Value.Substring(1)
                }
                elseif($Value.StartsWith("<") -or $Value.StartsWith(">")) {
                    $Operator = $Value[0]
                    $Value = $Value.Substring(1)
                }
                else {
                    $Operator = "LIKE"
                }

                if($_.Key -eq "ComputerNameFilter") {

                    $IP = $Null
                    $IPAddress = [Net.IPAddress]::TryParse($Value, [Ref] $IP)

                    if($IPAddress) {
                        $Clauses += @("IPAddress $Operator '$($Value)%'")
                    }
                    else {
                        # otherwise we have a computer name
                        $Clauses += @("ComputerName $Operator '$Value'")
                    }
                }
                else {
                    # chop off "...Filter"
                    $Field = $_.Key.Substring(0,$_.Key.Length-6)
                    $Clauses += @("$Field $Operator '$Value'")
                }
            }
            $Query += $Clauses -join " OR "
            $Query += ")"
        }
    }

    if($Parameters['OrderBy']) {
        $Query += "`nORDER BY $OrderBy"

        if($Parameters['Descending']) {
            $Query += " DESC"
        }
    }

    $Query
}


##############################################
#
# Functions that query or modified information
# in the SCCM database/server itself (as opposed) to
# client information in the SCCM database).
#
##############################################


function Find-SCCMDatabase {
<#
    .SYNOPSIS

        Takes a given SCCM database service identified by -ComputerName
        and returns all current database names.

    .PARAMETER ComputerName

        The name key of an SCCM database to create a temporary connection to for
        the query.

    .PARAMETER Credential

        A [Management.Automation.PSCredential] object that stores a SqlUserName and SqlPassword.

    .PARAMETER SqlUserName

        Specific MSSQL username to use instead of integrated Windows authentication.

    .PARAMETER SqlPassword

        Specific MSSQL username to use instead of integrated Windows authentication.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Position = 0, Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerName,

        [Parameter(ParameterSetName = 'PSCredential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Position = 1, Mandatory=$True, ParameterSetName = 'SQLCredentials')]
        [String]
        [ValidateNotNullOrEmpty()]
        $SqlUserName,

        [Parameter(Position = 2, Mandatory=$True, ParameterSetName = 'SQLCredentials')]
        [String]
        [ValidateNotNullOrEmpty()]
        $SqlPassword
    )

    process {
        try {
            $Session = New-SCCMSession -DatabaseName 'master' @PSBoundParameters
            $Session | Invoke-SQLQuery -Query "SELECT name FROM Sys.Databases WHERE name LIKE 'CM_%' AND state_desc = 'ONLINE'"
            $Session | Remove-SCCMSession
        }
        catch {
            Write-Error "Error enumerating server '$ComputerName' : $_"
        }
    }
}


function Get-SCCMApplicationCI {
<#
    .SYNOPSIS

        Returns applications that exist on the primary site server.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER CreatedByFilter

        Query only for results where the CreatedBy field matches the given filter.
        Wildcards accepted.

    .PARAMETER DisplayNameFilter

        Query only for results where the DisplayName field matches the given filter.
        Wildcards accepted.

    .PARAMETER CI_IDFilter

        Query only for results where the CI_ID field matches the given filter.
        Wildcards accepted.

    .PARAMETER DeploymentTypeName

        Query only for results where the DeploymentType field matches the given filter.
        Wildcards accepted.

    .PARAMETER DTInstallString

        Query only for results where the DTInstallString field matches the given filter.
        Wildcards accepted.

    .PARAMETER DateCreatedFilter

        Query only for results where the DateCreated field matches the given filter.
        Wildcards accepted.

    .PARAMETER LastModifiedFilter

        Query only for results where the LastModified field matches the given filter.
        Wildcards accepted.

    .PARAMETER LastModifiedByFilter

        Query only for results where the LastModifiedBy field matches the given filter.
        Wildcards accepted.

    .PARAMETER IsHidden

        Query only for results where the IsHidden field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMApplicationCI

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMApplicationCI -IsHiddenFilter 1

        Finds all hidden user deployed application configuration items.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("CreatedBy", "DisplayName", "CI_ID", "DeploymentTypeName", "Technology", "ContentSource", "DTInstallString", "DTUnInstallString", "DateCreated", "LastModified", "LastModifiedBy", "IsHidden")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $CreatedByFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DisplayNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CI_IDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DeploymentTypeNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DTInstallStringFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DateCreatedFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $LastModifiedFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $LastModifiedByFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $IsHiddenFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter        
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT DISTINCT TOP $Newest
         app.CreatedBy AS CreatedBy,
         app.DisplayName AS DisplayName,
         app.CI_ID AS CI_ID,
         dt.DisplayName AS DeploymentTypeName,
         dt.Technology AS Technology,
         v_ContentInfo.ContentSource AS ContentSource,
         v_ContentInfo.SourceSize AS ContentSourceSize,
         dt.SDMPackageDigest.value('declare namespace p1="http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest";
         (p1:AppMgmtDigest/p1:DeploymentType/p1:Installer/p1:CustomData/p1:InstallCommandLine)[1]', 'nvarchar(max)') AS DTInstallString,
         dt.SDMPackageDigest.value('declare namespace p1="http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest";
         (p1:AppMgmtDigest/p1:DeploymentType/p1:Installer/p1:CustomData/p1:UninstallCommandLine)[1]', 'nvarchar(max)') AS DTUnInstallString,
         app.DateCreated AS DateCreated,
         app.DateLastModified AS LastModified,
         app.LastModifiedBy AS LastModifiedBy,
         app.IsHidden AS IsHidden
    FROM 
         dbo.fn_ListDeploymentTypeCIs(1033) AS dt INNER JOIN
         dbo.fn_ListLatestApplicationCIs(1033) AS app ON dt.AppModelName = app.ModelName LEFT OUTER JOIN
         v_ContentInfo ON dt.ContentId = v_ContentInfo.Content_UniqueID
    WHERE   
         (dt.IsLatest = 1)
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMPackage {
<#
    .SYNOPSIS

        Returns SCCM packages that exist on the primary site server.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER PackageIDFilterFilter

        Query only for results where the PackageID field matches the given filter.
        Wildcards accepted.

    .PARAMETER PackageNameFilter

        Query only for results where the PackageName field matches the given filter.
        Wildcards accepted.    

    .PARAMETER ProgramNameFilter

        Query only for results where the ProgramName field matches the given filter.
        Wildcards accepted.    

    .PARAMETER CommandLineFilter

        Query only for results where the CommandLine field matches the given filter.
        Wildcards accepted.    

    .PARAMETER SourcePathFilter

        Query only for results where the SourcePath field matches the given filter.
        Wildcards accepted.    

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMPackage

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMPackage -Verbose -SourcePathFilter '\\PRIMARY.testlab.local\*'

        Returns packaged with a source location on \\PRIMARY.testlab.local\
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [String]
        [ValidateSet("PackageID", "PackageName", "ProgramName", "CommandLine", "SourcePath")]
        $OrderBy = "PackageID",

        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $PackageIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $PackageNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ProgramNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CommandLineFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SourcePathFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
        Program.PackageID AS PackageID,
        Package.Name AS PackageName,
        Program.ProgramName AS ProgramName,
        Program.CommandLine AS CommandLine,
        Package.PkgSourcePath AS SourcePath
    FROM 
        v_Program Program
    LEFT JOIN 
        v_Package Package on Package.PackageID = Program.PackageID
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMConfigurationItem {
<#
    .SYNOPSIS

        Returns SCCM configuration items that exist on the primary site server.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMConfigurationItem -CI_IDFilter 12345

        Returns the configuration item with ID 12345

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMConfigurationItem -IsHiddenFilter 1 -IsUserDefinedFilter 1

        Returns the all user defined configuration items that are marked as hidden.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("CI_UniqueID", "ModelId", "CIVersion", "SDMPackageDigest", "CIType_ID", "PolicyVersion", "DateCreated", "DateLastModified", "LastModifiedBy", "LocalDateLastReplicated", "CreatedBy", "PermittedUses", "IsBundle", "IsHidden", "IsTombstoned", "IsUserDefined", "IsEnabled", "IsExpired", "IsLatest", "SourceSite", "ContentSourcePath", "ApplicabilityCondition", "Precedence", "CI_CRC", "IsUserCI", "ApplicableAtUserLogon", "RevisionTag", "SEDOComponentID", "MinRequiredVersion")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $CI_IDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CI_UniqueIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DateCreatedFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DateLastModifiedFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $LastModifiedByFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CreatedByFilter,

        [String]
        [ValidateSet("0", "1")]
        $IsHiddenFilter,

        [String]
        [ValidateSet("0", "1")]
        $IsUserDefinedFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT TOP $Newest
    * from CI_ConfigurationItems QUERY
WHERE
     CI_ID is not null
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Set-SCCMConfigurationItem {
<#
    .SYNOPSIS

        Sets a field to a particular value for a SCCM configuration keyed by CI_ID.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER CI_ID

        The configuration interface ID of the application to manipulate.
        You can retrieve this with Get-SCCMApplication or Get-SCCMConfigurationItem.

    .PARAMETER Column

        The column/field name to set.

    .PARAMETER Value

        Value to set the Field to.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Set-SCCMConfigurationItem -CI_ID 12345 -Field IsHidden -Value 1

        Set the configuration item with If 12345 to be hidden from the SCCM GUi.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Parameter(Mandatory=$True)]
        [String]
        $CI_ID,

        [Parameter(Mandatory=$True)]
        [String]
        [ValidateSet("CI_UniqueID", "ModelId", "CIVersion", "CIType_ID", "PolicyVersion", "DateCreated", "DateLastModified", "LastModifiedBy", "LocalDateLastReplicated", "CreatedBy", "PermittedUses", "IsBundle", "IsHidden", "IsTombstoned", "IsUserDefined", "IsEnabled", "IsExpired", "IsLatest", "SourceSite", "ContentSourcePath", "ApplicabilityCondition", "Precedence", "CI_CRC", "IsUserCI", "ApplicableAtUserLogon", "RevisionTag", "SEDOComponentID", "MinRequiredVersion")]
        $Column,

        [Parameter(Mandatory=$True)]
        [String]
        $Value,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        # get the SQL wildcards correct
        $CI_ID = $CI_ID.Replace('*', '%')

        $Query = @"
UPDATE 
    CI_ConfigurationItems
SET 
    $Column=$Value
WHERE
    CI_ID LIKE '$CI_ID'
"@
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


##############################################
#
# Common defensive queries involving information
# collected from client machines.
#
##############################################

function Get-SCCMService {
<#
    .SYNOPSIS

        Returns information on the current set of running services as of the
        last SCCM agent query/checkin.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SCCMTimeStampFilter

        Query only for results where the SCCM TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SCCMTimeStampFilter '>2012-03-01 00:00:00.000')

    .PARAMETER DescriptionFilter

        Query only for results where the Description field matches the given filter.
        Wildcards accepted.

    .PARAMETER NameFilter

        Query only for results where the Name field matches the given filter.
        Wildcards accepted.

    .PARAMETER DisplayNameFilter

        Query only for results where the DisplayName field matches the given filter.
        Wildcards accepted.

    .PARAMETER PathNameFilter

        Query only for results where the PathName field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> $Session = Get-SCCMSession
        PS C:\> Get-SCCMService -Session $Session

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMService -ComputerFilterName WINDOWS1

        Returns service information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMService -ComputerFilterName WINDOWS* -Newest 10 -OrderBy DisplayName -Descending

        Return the top 10 services for system matching the computer name WINDOWS*, ordered by
        descending DisplayName

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMService -PathNameFilter "C:\Temp\* or C:\Malicious\*"

        Returns services with a path name starting with C:\Temp\ or C:\Malicious\
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SCCMTimeStamp", "Caption","Description","DisplayName", "ErrorControl", "ExitCode", "Name", "PathName", "ProcessId", "ServiceType", "Started", "StartMode", "State")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SCCMTimeStampFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DisplayNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $PathNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SCCMTimeStamp,
         QUERY.Caption0 as Caption,
         QUERY.Description0 as Description,
         QUERY.DisplayName0 as DisplayName,
         QUERY.ErrorControl0 as ErrorControl,
         QUERY.ExitCode0 as ExitCode,
         QUERY.Name0 as Name,
         QUERY.PathName0 as PathName,
         QUERY.ProcessId0 as ProcessId,
         QUERY.ServiceType0 as ServiceType,
         QUERY.Started0 as Started,
         QUERY.StartMode0 as StartMode,
         QUERY.State0 as State
    FROM
         v_R_System COMPUTER
    JOIN
         v_HS_SERVICE QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMServiceHistory {
<#
    .SYNOPSIS

        Returns information on the historical set of running services as of the
        last SCCM agent query/checkin.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SCCMTimeStampFilter

        Query only for results where the SCCM TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SCCMTimeStampFilter '>2012-03-01 00:00:00.000')

    .PARAMETER DescriptionFilter

        Query only for results where the Description field matches the given filter.
        Wildcards accepted.

    .PARAMETER NameFilter

        Query only for results where the Name field matches the given filter.
        Wildcards accepted.

    .PARAMETER DisplayNameFilter

        Query only for results where the DisplayName field matches the given filter.
        Wildcards accepted.

    .PARAMETER PathNameFilter

        Query only for results where the PathName field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMServiceHistory

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMServiceHistory -ComputerFilterName WINDOWS1

        Returns historical service information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMServiceHistory -ComputerFilterName WINDOWS* -Newest 10 -OrderBy DisplayName -Descending

        Return the top 10 historical services for system matching the computer name WINDOWS*, ordered by
        descending DisplayName
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SCCMTimestamp", "Caption","Description","DisplayName", "ErrorControl", "ExitCode", "Name", "PathName", "ProcessId", "ServiceType", "Started", "StartMode", "State")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SCCMTimeStampFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DisplayNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $PathNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SCCMTimeStamp,
         QUERY.Caption0 as Caption,
         QUERY.Description0 as Description,
         QUERY.DisplayName0 as DisplayName,
         QUERY.ErrorControl0 as ErrorControl,
         QUERY.ExitCode0 as ExitCode,
         QUERY.Name0 as Name,
         QUERY.PathName0 as PathName,
         QUERY.ProcessId0 as ProcessId,
         QUERY.ServiceType0 as ServiceType,
         QUERY.Started0 as Started,
         QUERY.StartMode0 as StartMode,
         QUERY.State0 as State
    FROM
         v_R_System COMPUTER
    JOIN
         v_GS_SERVICE QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMAutoStart {
<#
    .SYNOPSIS

        Returns information on the set of autostart programs as of the
        last SCCM agent query/checkin.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SCCMTimeStampFilter

        Query only for results where the SCCM TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SCCMTimeStampFilter '>2012-03-01 00:00:00.000')

    .PARAMETER DescriptionFilter

        Query only for results where the Description field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileNameFilter

        Query only for results where the FileName field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileVersionFilter

        Query only for results where the FileVersion field matches the given filter.
        Wildcards accepted.

    .PARAMETER ProductFilter

        Query only for results where the Product field matches the given filter.
        Wildcards accepted.

    .PARAMETER PublisherFilter

        Query only for results where the Publisher field matches the given filter.
        Wildcards accepted.

    .PARAMETER StartupValueFilter

        Query only for results where the StartupValue field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMAutoStart

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMAutoStart -ComputerFilterName WINDOWS1

        Returns autostate information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMAutoStart -DescriptionFilter *malicious*

        Returns autostate information for entries with *malicious* in the description.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SCCMTimestamp", "Description", "FileName", "FileVersion", "Location", "Product", "Publisher", "StartupType", "StartupValue")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SCCMTimeStampFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileVersionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ProductFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $PublisherFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $StartupValueFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SCCMTimeStamp,
         QUERY.Description0 as Description,
         QUERY.FileName0 as FileName,
         QUERY.FileVersion0 as FileVersion,
         QUERY.Location0 as Location,
         QUERY.Product0 as Product,
         QUERY.Publisher0 as Publisher,
         QUERY.StartupType0 as StartupType,
         QUERY.StartupValue0 as StartupValue
    FROM
         v_R_System COMPUTER
    JOIN
         v_GS_AUTOSTART_SOFTWARE QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMProcess {
<#
    .SYNOPSIS

        Returns information on the set of currently running processes as of the
        last SCCM agent query/checkin.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SCCMTimeStampFilter

        Query only for results where the SCCM TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SCCMTimeStampFilter '>2012-03-01 00:00:00.000')

    .PARAMETER CaptionFilter
        
        Query only for results where the Caption field matches the given filter.
        Wildcards accepted.

    .PARAMETER CreationDateFilter
        
        Query only for results where the CreationDate field matches the given filter.
        Wildcards accepted.

    .PARAMETER DescriptionFilter
        
        Query only for results where the Description field matches the given filter.
        Wildcards accepted.

    .PARAMETER ExecutablePathFilter
        
        Query only for results where the ExecutablePath field matches the given filter.
        Wildcards accepted.

    .PARAMETER NameFilter
        
        Query only for results where the Name field matches the given filter.
        Wildcards accepted.

    .PARAMETER ParentProcessIdFilter
        
        Query only for results where the ParentProcessId field matches the given filter.

    .PARAMETER ProcessIdFilter
    
        Query only for results where the ProcessId field matches the given filter.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMProcess

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMProcess -ComputerFilterName WINDOWS1

        Returns process information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMProcess -NameFilter *malicious*

        Returns process information for any process with *malicious* in the name.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SCCMTimestamp", "Caption", "CreationDate", "Description", "ExecutablePath", "Name", "ParentProcessId", "ProcessId")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SCCMTimeStampFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CaptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CreationDateFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ExecutablePathFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ParentProcessIdFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ProcessIdFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SCCMTimeStamp,
         QUERY.Caption0 as Caption,
         QUERY.CreationDate0 as CreationDate,
         QUERY.Description0 as Description,
         QUERY.ExecutablePath0 as ExecutablePath,
         QUERY.Name0 as Name,
         QUERY.ParentProcessId0 as ParentProcessId,
         QUERY.ProcessId0 as ProcessId
    FROM
         v_R_System COMPUTER
    JOIN
         v_GS_PROCESS QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMProcessHistory {
<#
    .SYNOPSIS

        Returns information on the historical set of running processes as of the
        last SCCM agent query/checkin.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SCCMTimeStampFilter

        Query only for results where the SCCM TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SCCMTimeStampFilter '>2012-03-01 00:00:00.000')

    .PARAMETER CaptionFilter
        
        Query only for results where the Caption field matches the given filter.
        Wildcards accepted.

    .PARAMETER CreationDateFilter
        
        Query only for results where the CreationDate field matches the given filter.
        Wildcards accepted.

    .PARAMETER DescriptionFilter
        
        Query only for results where the Description field matches the given filter.
        Wildcards accepted.

    .PARAMETER ExecutablePathFilter
        
        Query only for results where the ExecutablePath field matches the given filter.
        Wildcards accepted.

    .PARAMETER NameFilter
        
        Query only for results where the Name field matches the given filter.
        Wildcards accepted.

    .PARAMETER ParentProcessIdFilter
        
        Query only for results where the ParentProcessId field matches the given filter.

    .PARAMETER ProcessIdFilter
    
        Query only for results where the ProcessId field matches the given filter.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMProcessHistory

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMProcessHistory -ComputerFilterName WINDOWS1

        Returns historical process information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMProcessHistory -NameFilter *malicious*

        Returns historical process information for any process with *malicious* in the name.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SCCMTimestamp", "Caption", "CreationDate", "Description", "ExecutablePath", "Name", "ParentProcessId", "ProcessId")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SCCMTimeStampFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CaptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CreationDateFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ExecutablePathFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ParentProcessIdFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ProcessIdFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SCCMTimeStamp,
         QUERY.Caption0 as Caption,
         QUERY.CreationDate0 as CreationDate,
         QUERY.Description0 as Description,
         QUERY.ExecutablePath0 as ExecutablePath,
         QUERY.Name0 as Name,
         QUERY.ParentProcessId0 as ParentProcessId,
         QUERY.ProcessId0 as ProcessId
    FROM
         v_R_System COMPUTER
    JOIN
         v_HS_PROCESS QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMRecentlyUsedApplication {
<#
    .SYNOPSIS

        Returns information on the set of recently used applications as of the
        last SCCM agent query/checkin.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SCCMTimeStampFilter

        Query only for results where the SCCM TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SCCMTimeStampFilter '>2012-03-01 00:00:00.000')

    .PARAMETER CompanyNameFilter

        Query only for results where the CompanyName field matches the given filter.
        Wildcards accepted.

    .PARAMETER ExplorerFileNameFilter

        Query only for results where the ExplorerFileName field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileDescriptionFilter

        Query only for results where the FileDescription field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileSizeFilter

        Query only for results where the FileSize field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileVersionFilter

        Query only for results where the FileVersion field matches the given filter.
        Wildcards accepted.

    .PARAMETER FolderPathFilter

        Query only for results where the FolderPath field matches the given filter.
        Wildcards accepted.

    .PARAMETER LastUsedTimeFilter

        Query only for results where the LastUsedTime field matches the given filter.
        Wildcards accepted.

    .PARAMETER LastUserNameFilter

        Query only for results where the LastUserName field matches the given filter.
        Wildcards accepted.

    .PARAMETER OriginalFileNameFilter

        Query only for results where the OriginalFileName field matches the given filter.
        Wildcards accepted.

    .PARAMETER ProductNameFilter

        Query only for results where the ProductName field matches the given filter.
        Wildcards accepted.

    .PARAMETER ProductVersionFilter

        Query only for results where the ProductVersion field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMRecentlyUsedApplication

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMRecentlyUsedApplication -ComputerFilterName WINDOWS1

        Returns recently used applications just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMRecentlyUsedApplication -FileDescriptionFilter *mimikatz*

        Returns recently used applications with *mimikatz* in the description.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SCCMTimestamp", "CompanyName", "ExplorerFileName", "FileDescription", "FileSize", "FileVersion", "FolderPath", "LastUsedTime", "LastUserName", "OriginalFileName", "ProductName", "ProductVersion")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SCCMTimeStampFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CompanyNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ExplorerFileNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileDescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileSizeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileVersionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FolderPathFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $LastUsedTimeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $LastUserNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $OriginalFileNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ProductNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ProductVersionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SCCMTimeStamp,
         QUERY.CompanyName0 as CompanyName,
         QUERY.ExplorerFileName0 as ExplorerFileName,
         QUERY.FileDescription0 as FileDescription,
         QUERY.FileSize0 as FileSize,
         QUERY.FileVersion0 as FileVersion,
         QUERY.FolderPath0 as FolderPath,
         QUERY.LastUsedTime0 as LastUsedTime,
         QUERY.LastUserName0 as LastUserName,
         QUERY.OriginalFileName0 as OriginalFileName,
         QUERY.ProductName0 as ProductName,
         QUERY.ProductVersion0 as ProductVersion
    FROM
         v_R_System COMPUTER
    JOIN
         v_GS_CCM_RECENTLY_USED_APPS QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMDriver {
<#
    .SYNOPSIS

        Returns information on the set of currently loaded system drivers as of the
        last SCCM agent query/checkin.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SCCMTimeStampFilter

        Query only for results where the SCCM TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SCCMTimeStampFilter '>2012-03-01 00:00:00.000')

    .PARAMETER CaptionFilter

        Query only for results where the Caption field matches the given filter.
        Wildcards accepted.

    .PARAMETER DescriptionFilter

        Query only for results where the Description field matches the given filter.
        Wildcards accepted.

    .PARAMETER DisplayNameFilter

        Query only for results where the DisplayName field matches the given filter.
        Wildcards accepted.

    .PARAMETER NameFilter

        Query only for results where the Name field matches the given filter.
        Wildcards accepted.

    .PARAMETER PathNameFilter

        Query only for results where the PathName field matches the given filter.
        Wildcards accepted.

    .PARAMETER ServiceTypeFilter

        Query only for results where the ServiceType field matches the given filter.
        Wildcards accepted.

    .PARAMETER StateFilter

        Query only for results where the State field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMDriver

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMDriver -ComputerFilterName WINDOWS1

        Returns driver information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMDriver -PathNameFilter C:\Temp\*

        Returns information on all drivers located in C:\Temp\
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SCCMTimestamp", "Caption", "Description", "DisplayName", "ErrorControl", "ExitCode", "Name", "PathName", "ServiceType", "StartMode", "State")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SCCMTimeStampFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CaptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DisplayNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $PathNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ServiceTypeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $StateFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SCCMTimeStamp,
         QUERY.Caption0 as Caption,
         QUERY.Description0 as Description,
         QUERY.DisplayName0 as DisplayName,
         QUERY.ErrorControl0 as ErrorControl,
         QUERY.ExitCode0 as ExitCode,
         QUERY.Name0 as Name,
         QUERY.PathName0 as PathName,
         QUERY.ServiceType0 as ServiceType,
         QUERY.StartMode0 as StartMode,
         QUERY.State0 as State
    FROM
         v_R_System COMPUTER
    JOIN
         v_GS_SYSTEM_DRIVER QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMConsoleUsage {
<#
    .SYNOPSIS

        Returns historical information on user console usage as of the
        last SCCM agent query/checkin.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SCCMTimeStampFilter

        Query only for results where the SCCM TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SCCMTimeStampFilter '>2012-03-01 00:00:00.000')

    .PARAMETER SystemConsoleUserFilter

        Query only for results where the SystemConsoleUser field matches the given filter.
        Wildcards accepted.

    .PARAMETER LastConsoleUseFilter

        Query only for results where the LastConsoleUse field matches the given filter.
        Wildcards accepted.

    .PARAMETER NumberOfConsoleLogonsFilter

        Query only for results where the NumberOfConsoleLogons field matches the given filter.
        Wildcards accepted.

    .PARAMETER TotalUserConsoleMinutesFilter

        Query only for results where the TotalUserConsoleMinutes field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMConsoleUsage

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMConsoleUsage -ComputerFilterName WINDOWS1

        Returns console usage information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMConsoleUsage -SystemConsoleUserFilter DOMAIN\john

        Returns console usage information for the user 'DOMAIN\john' from all inventoried machines.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SCCMTimestamp", "SystemConsoleUser", "LastConsoleUse", "NumberOfConsoleLogons", "TotalUserConsoleMinutes")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SCCMTimeStampFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SystemConsoleUserFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $LastConsoleUseFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $NumberOfConsoleLogonsFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $TotalUserConsoleMinutesFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SCCMTimeStamp,
         QUERY.SystemConsoleUser0 as SystemConsoleUser,
         QUERY.LastConsoleUse0 as LastConsoleUse,
         QUERY.NumberOfConsoleLogons0 as NumberOfConsoleLogons,
         QUERY.TotalUserConsoleMinutes0 as TotalUserConsoleMinutes
    FROM
         v_R_System COMPUTER
    JOIN
         v_GS_SYSTEM_CONSOLE_USER QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMSoftwareFile {
<#
    .SYNOPSIS

        Returns information on inventoried non-Microsoft software files.
        TThis option is not enabled by default in SCCM- we recommend setting SCCM
        to inventory all *.exe files on hosts.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileNameFilter

        Query only for results where the FileName field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileDescriptionFilter

        Query only for results where the FileDescription field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileVersionFilter

        Query only for results where the FileVersion field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileSizeFilter

        Query only for results where the FileSize field matches the given filter.
        Wildcards accepted.

    .PARAMETER FilePathFilter

        Query only for results where the FilePath field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileModifiedDateFilter

        Query only for results where the FileModifiedDate field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMSoftwareFile

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMSoftwareFile -ComputerFilterName WINDOWS1

        Returns software file information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMSoftwareFile -FilePathFilter C:\Temp\*

        Returns information on software files located in C:\Temp\
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("FileName", "FileDescription", "FileVersion", "FileSize", "FilePath", "FileModifiedDate")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileDescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileVersionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileSizeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FilePathFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileModifiedDateFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.FileName as FileName,
         QUERY.FileDescription as FileDescription,
         QUERY.FileVersion as FileVersion,
         QUERY.FileSize as FileSize,
         QUERY.FilePath as FilePath,
         QUERY.FileModifiedDate as FileModifiedDate
    FROM
         v_R_System COMPUTER
    JOIN
         v_GS_SoftwareFile QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMBrowserHelperObject {
<#
    .SYNOPSIS

        Returns information on discovered browser helper objects.
        This option is not enabled by default.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SCCMTimeStampFilter

        Query only for results where the SCCM TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SCCMTimeStampFilter '>2012-03-01 00:00:00.000')

    .PARAMETER BinFileVersionFilter

        Query only for results where the BinFileVersion field matches the given filter.
        Wildcards accepted.

    .PARAMETER BinProductVersionFilter

        Query only for results where the BinProductVersion field matches the given filter.
        Wildcards accepted.

    .PARAMETER DescriptionFilter

        Query only for results where the Description field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileNameFilter

        Query only for results where the FileName field matches the given filter.
        Wildcards accepted.

    .PARAMETER FileVersionFilter

        Query only for results where the FileVersion field matches the given filter.
        Wildcards accepted.

    .PARAMETER ProductFilter

        Query only for results where the Product field matches the given filter.
        Wildcards accepted.

    .PARAMETER ProductVersionFilter

        Query only for results where the ProductVersion field matches the given filter.
        Wildcards accepted.

    .PARAMETER PublisherFilter

        Query only for results where the Publisher field matches the given filter.
        Wildcards accepted.

    .PARAMETER VersionFilter

        Query only for results where the Version field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMBrowserHelperObject

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMBrowserHelperObject -ComputerFilterName WINDOWS1

        Returns browser helper object information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMBrowserHelperObject -DescriptionFilter *malicious*

        Returns browser helper object information with a wildcard match for *malicious* in the description field.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SCCMTimestamp", "BinFileVersion", "BinProductVersion", "Description", "FileName", "FileVersion", "Product", "ProductVersion", "Publisher", "Version")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SCCMTimeStampFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $BinFileVersionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $BinProductVersionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FileVersionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ProductFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ProductVersionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $PublisherFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $VersionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SCCMTimeStamp,
         QUERY.BinFileVersion0 as BinFileVersion,
         QUERY.BinProductVersion0 as BinProductVersion,
         QUERY.Description0 as Description,
         QUERY.FileName0 as FileName,
         QUERY.FileVersion0 as FileVersion,
         QUERY.Product0 as Product,
         QUERY.ProductVersion0 as ProductVersion,
         QUERY.Publisher0 as Publisher,
         QUERY.Version0 as Version
    FROM
         v_R_System COMPUTER
    JOIN
         v_GS_BROWSER_HELPER_OBJECT QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMShare {
<#
    .SYNOPSIS

        Returns information on discovered shares.
        This option is not enabled by default.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SCCMTimeStampFilter

        Query only for results where the SCCM TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SCCMTimeStampFilter '>2012-03-01 00:00:00.000')

    .PARAMETER CaptionFilter

        Query only for results where the Caption field matches the given filter.
        Wildcards accepted.

    .PARAMETER DescriptionFilter

        Query only for results where the Description field matches the given filter.
        Wildcards accepted.

    .PARAMETER NameFilter

        Query only for results where the Name field matches the given filter.
        Wildcards accepted.

    .PARAMETER PathFilter

        Query only for results where the Path field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMShare

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMShare -ComputerFilterName WINDOWS1

        Returns share information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMShare -DescriptionFilter *secret*

        Returns share information with a wildcard match for *secret* in the description field.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SCCMTimestamp", "Caption", "Description", "Name", "Path")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SCCMTimeStampFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CaptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $PathFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SCCMTimeStamp,
         QUERY.Caption0 as Caption,
         QUERY.Description0 as Description,
         QUERY.Name0 as Name,
         QUERY.Path0 as Path
    FROM
         v_R_System COMPUTER
    JOIN
         v_GS_SHARE QUERY ON COMPUTER.ResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


function Get-SCCMPrimaryUser {
<#
    .SYNOPSIS

        Returns information on primary users set for specific machine names.
        This option is not enabled by default.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying SCCM SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER Unique_User_NameFilter

        Query only for results where the Unique_User_Name field matches the given filter.
        Wildcards accepted.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMPrimaryUser

        Runs the query against all current SCCM sessions.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Get-SCCMPrimaryUser -ComputerFilterName WINDOWS1

        Returns primary user information for just the WINDOWS1 machine.

    .EXAMPLE

        PS C:\> Get-SCCMPrimaryUser | Get-SCCMPrimaryUser -Unique_User_NameFilter "DOMAIN\will"

        Returns the locations where DOMAIN\Will is a primary user
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("ComputerName", "IPAddress", "UserResourceID", "Unique_User_Name")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Unique_User_NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
-- MIN_SCCM_VERSION = 5
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY2.UserResourceID as UserResourceID,
         QUERY.Unique_User_Name0 as Unique_User_Name
    FROM
         v_R_System COMPUTER
    JOIN
         vMDMUsersPrimaryMachines QUERY2 ON COMPUTER.ResourceID = QUERY2.MachineID
    JOIN
         v_R_User QUERY ON QUERY2.UserResourceID = QUERY.ResourceID
    JOIN
         v_GS_NETWORK_ADAPTER_CONFIGUR ADAPTER on COMPUTER.ResourceID = ADAPTER.ResourceID
    WHERE
         ADAPTER.IPAddress0 is not null
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-FilterQuery -Query $Query -Parameters $PSBoundParameters
    }

    process {   
        Invoke-SQLQuery -Session $Session -Query $Query
    }
}


##############################################
#
# Common meta-queries to search for 'bad' things
# from information collected from client machines.
#
##############################################

function Find-SCCMRenamedCMD {
<#
    .SYNOPSIS

        Finds renamed cmd.exe executables using Get-SCCMRecentlyUsedApplication
        and appropriate filters.

        Adapted from slide 16 in John McLeod and Mike-Pilkington's
        "Mining for Evil" presentation.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Find-SCCMRenamedCMD
        
        Runs the query against all current SCCM sessions.

    .LINK

        https://digital-forensics.sans.org/summit-archives/DFIR_Summit/Mining-for-Evil-John-McLeod-Mike-Pilkington.pdf
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session
    )

    process {
        # find recently launched executables in C:\ with 'Windows Command Processor' as the Description
        #   and a name not like cmd.exe
        Get-SCCMRecentlyUsedApplication -Session $Session -FolderPathFilter "C:\*" -FileDescriptionFilter 'Windows Command Processor' -ExplorerFileNameFilter "!cmd.exe"
    }
}


function Find-SCCMUnusualEXE {
<#
    .SYNOPSIS

        Finds recently launched applications that don't end in *.exe using
        Get-SCCMRecentlyUsedApplication and appropriate filters.

        Adapted from slide 18 in John McLeod and Mike-Pilkington's
        "Mining for Evil" presentation.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Find-SCCMUnusualEXE

        Runs the query against all current SCCM sessions.

    .LINK

        https://digital-forensics.sans.org/summit-archives/DFIR_Summit/Mining-for-Evil-John-McLeod-Mike-Pilkington.pdf
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session
    )

    process {
        # find recently launched executables in C:\ that don't end in *.exe
        Get-SCCMRecentlyUsedApplication -Session $Session -FolderPathFilter "C:\*" -ExplorerFileNameFilter "!*.exe"
    }
}


function Find-SCCMRareApplication {
<#
    .SYNOPSIS

        Finds the rarest -Limit <X> recently launched applications that don't end in *.exe using
        Get-SCCMRecentlyUsedApplication and appropriate filters.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .PARAMETER Limit

        The limit of number of rarest applications to return. Default of 100.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Find-SCCMRareApplication -Limit 10

        Finds the 10 rarest launched applications.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session,

        [Int]
        [ValidateNotNullOrEmpty()]
        $Limit = 100
    )

    process {
        # find all recently used applications, group by the launched ExplorerFileName,
        #   sort by the count and return the top -Limit <X> number
        Get-SCCMRecentlyUsedApplication -Session $Session | Group-Object -Property ExplorerFileName | Sort-Object -Property Count | Select-Object -First $Limit
    }
}


function Find-SCCMPostExploitation {
<#
    .SYNOPSIS

        Finds recently launched applications commonly used in post-exploitation.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Find-SCCMPostExploitation

        Runs the query against all current SCCM sessions.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session
    )

    process {
        # common post-exploitation tool names to search for in recently launched applications
        $PostExTools = "net.exe", "whoami.exe", "runas.exe", "rdpclip.exe", "at.exe", "schtasks.exe", "wmic.exe", "tasklist.exe", "sc.exe", "psexec.exe", "hostname.exe", "ver.exe", "dsquery.exe", "reg.exe", "*nmap*", "*mimikatz*", "*wce*", "*fgdump*", "*cain*", "*abel*", "*superscan*"
        Get-SCCMRecentlyUsedApplication -Session $Session -ExplorerFileNameFilter $($PostExTools -join " or ")
    }
}


function Find-SCCMPostExploitationFile {
<#
    .SYNOPSIS

        Finds indexed .exe's commonly used in post-exploitation.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Find-SCCMPostExploitationFile

        Runs the query against all current SCCM sessions.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session
    )

    process {
        # common post-exploitation tool names to search for in inventoried files
        $PostExTools = "net.exe", "whoami.exe", "runas.exe", "rdpclip.exe", "at.exe", "schtasks.exe", "wmic.exe", "tasklist.exe", "sc.exe", "psexec.exe", "hostname.exe", "ver.exe", "dsquery.exe", "reg.exe", "*nmap*", "*mimikatz*", "*wce*", "*fgdump*", "*cain*", "*abel*", "*superscan*"

        Get-SCCMSoftwareFile -Session $Session -FileNameFilter $($PostExTools -join " or ")
    }
}


function Find-SCCMMimikatz {
<#
    .SYNOPSIS

        Finds launched mimikatz instances by searching the 'FileDescription' and 'CompanyName' fields of recently launched applications.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Find-SCCMMimikatz

        Runs the query against all current SCCM sessions.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session
    )

    process {
        Get-SCCMRecentlyUsedApplication -Session $Session -Filter "(CompanyName LIKE '%gentilkiwi%') OR (FileDescription LIKE '%mimikatz%')"
    }
}


function Find-SCCMMimikatzFile {
<#
    .SYNOPSIS

        Finds inventoried mimikatz.exe instances by searching the 'FileDescription'
        field of inventoried .exe's.

    .PARAMETER Session

        The custom PowerSCCM.Session object to query, generated/stored by New-SCCMSession
        and retrievable with Get-SCCMSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SCCMSession | Find-SCCMMimikatzFile

        Runs the query against all current SCCM sessions.
#>
    [CmdletBinding()]
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSCCM.Session'})]
        $Session
    )

    process {
        Get-SCCMSoftwareFile -Session $Session -FileDescriptionFilter "*mimikatz*"
    }
}
