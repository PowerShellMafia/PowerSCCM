#requires -version 2


# global store for established Sccm connection objects
[System.Collections.ArrayList]$Script:SccmSessions = @()
$Script:SccmSessionCounter = 0


# make sure sessions are killed on powershell.exe exit
$Null = Register-EngineEvent -SourceIdentifier ([Management.Automation.PsEngineEvent]::Exiting) -Action {
        Write-Warning 'Cleaning up any existing Sccm connections!'
        Get-SccmSession | Remove-SccmSession
}


function New-SccmSession {
<#
    .SYNOPSIS

        Initiates a new Sccm database connection, returning a custom PowerSccm.Session
        object that stores a unique Id and Name, as well as permission and connection
        information. Also stores the PowerSccm.Session object in the $Script:SccmSessions 
        array for later access by Get-SccmSession.

    .PARAMETER ComputerName

        The hostname of the Sccm database server.

    .PARAMETER SiteCode

        The three letter site code of the Sccm distribution site. Discoverable with Find-SccmSiteCode.

    .PARAMETER ConnectionType

        The method to connect to the remote Sccm server. 'WMI' uses a WMI connection and the
        Sccm SMS_ WMI classes. 'Database'/'DB'/'SQL' connects to the Sccm MSSQL backend database.
        Default to WMI.

    .PARAMETER Credential

        A [Management.Automation.PSCredential] object that stores a SqlUserName and SqlPassword
        or a domain credential to use for WMI connections.

    .PARAMETER SqlUserName

        Specific MSSQL username to use instead of integrated Windows authentication.

    .PARAMETER SqlPassword

        Specific MSSQL username to use instead of integrated Windows authentication.

    .EXAMPLE

        PS C:\> New-SccmSession -ComputerName SccmServer -SiteCode LOL
    
        Connect to the LOL sitecode namespace on SccmServer over WMI.    

    .EXAMPLE

        PS C:\> New-SccmSession -ComputerName SccmServer -SiteCode LOL -ConnectionType Database
    
        Connect to the CM_LOL MSSQL database on SccmServer.

    .EXAMPLE

        PS C:\> New-SccmSession -ComputerName Sccm -SiteCode LOL -SqlUserName sqladmin -SqlPassword 'Password123!'

        Connect to the CM_LOL database on SccmServer using explicit MSSQL credentials
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
        [ValidatePattern('^[A-Za-z]{3}$')]
        $SiteCode,

        [Parameter(Position = 2)]
        [String]
        [ValidateSet("Database", "DB", "SQL", "WMI")]
        $ConnectionType = "SQL",

        [Parameter(Position = 3)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(ParameterSetName = 'SQLCredentials', Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $SqlUserName,

        [Parameter(ParameterSetName = 'SQLCredentials', Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $SqlPassword
    )

    if(($ConnectionType -notlike "WMI") -or $PSBoundParameters['SqlUserName']) {
        # if we're connecting to the Sccm MSSQL database
        try {

            $DatabaseName = "CM_$SiteCode"
            Write-Verbose "Connecting to Sccm server\database $ComputerName\$DatabaseName"

            $SQLConnection = New-Object System.Data.SQLClient.SQLConnection

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

            $Script:SccmSessionCounter += 1

            $SccmSessionObject = New-Object PSObject
            $SccmSessionObject | Add-Member Noteproperty 'Id' $Script:SccmSessionCounter
            $SccmSessionObject | Add-Member Noteproperty 'Name' $($SiteCode + $Script:SccmSessionCounter)
            $SccmSessionObject | Add-Member Noteproperty 'ComputerName' $ComputerName
            $SccmSessionObject | Add-Member Noteproperty 'Credential' $Null
            $SccmSessionObject | Add-Member Noteproperty 'SiteCode' $SiteCode
            $SccmSessionObject | Add-Member Noteproperty 'ConnectionType' $ConnectionType
            $SccmSessionObject | Add-Member Noteproperty 'SccmVersion' $Null
            $SccmSessionObject | Add-Member Noteproperty 'Permissions' $Null
            $SccmSessionObject | Add-Member Noteproperty 'Provider' $SQLConnection
            
            # add in our custom object type
            $SccmSessionObject.PSObject.TypeNames.Add('PowerSccm.Session')
            
            # get the Sccm version used
            $SccmVersionQuery = "SELECT TOP 1 LEFT(Client_Version0,CHARINDEX('.',Client_Version0)-1) as Sccm_Version FROM v_R_System"
            $SccmVersion = (Invoke-SccmQuery -Session $SccmSessionObject -Query $SccmVersionQuery).Sccm_Version
            $SccmSessionObject.SccmVersion = $SccmVersion

            # get the current user database permissions
            $PermissionsQuery = "SELECT permission_name FROM fn_my_permissions (NULL, 'DATABASE')"
            $Permissions = Invoke-SccmQuery -Session $SccmSessionObject -Query $PermissionsQuery | ForEach-Object { $_.permission_name }
            $SccmSessionObject.Permissions = $Permissions

            if(!($Permissions -contains "SELECT")) {
                Write-Warning "Current user does not have SELECT permissions!"
            }
            if(!($Permissions -contains "UPDATE")) {
                Write-Warning "Current user does not have UPDATE permissions!"
            }
        }

        catch {
            Write-Error "[!] Error connecting to $ComputerName\$DatabaseName : $_"
        }
    }

    else {

        Write-Verbose "Connecting to Sccm server\site $ComputerName\$SiteCode via WMI"

        try {

            $Query = "SELECT * FROM SMS_ProviderLocation where SiteCode = '$SiteCode'"
            if($Credential) {
                $SccmProvider = Get-WmiObject -ComputerName $ComputerName -Query $Query -Namespace "root\sms" -Credential $Credential
            }
            else {
                $SccmProvider = Get-WmiObject -ComputerName $ComputerName -Query $Query -Namespace "root\sms"
            }

            $Script:SccmSessionCounter += 1

            $SccmSessionObject = New-Object PSObject
            $SccmSessionObject | Add-Member Noteproperty 'Id' $Script:SccmSessionCounter
            $SccmSessionObject | Add-Member Noteproperty 'Name' $($SiteCode + $Script:SccmSessionCounter)
            $SccmSessionObject | Add-Member Noteproperty 'ComputerName' $ComputerName
            $SccmSessionObject | Add-Member Noteproperty 'Credential' $Credential
            $SccmSessionObject | Add-Member Noteproperty 'SiteCode' $SiteCode
            $SccmSessionObject | Add-Member Noteproperty 'ConnectionType' $ConnectionType
            $SccmSessionObject | Add-Member Noteproperty 'SccmVersion' $Null
            $SccmSessionObject | Add-Member Noteproperty 'Permissions' @("ALL")
            $SccmSessionObject | Add-Member Noteproperty 'Provider' $SccmProvider
            
            # add in our custom object type
            $SccmSessionObject.PSObject.TypeNames.Add('PowerSccm.Session')

            $SccmVersion = (Invoke-SccmQuery -Session $SccmSessionObject -Query "SELECT * FROM SMS_R_System" | Select-Object -First 1 -Property ClientVersion).ClientVersion.Split(".")[0]
            $SccmSessionObject.SccmVersion = $SccmVersion
        }
        catch {
            Write-Error "[!] Error connecting to $ComputerName\$WMISiteCode via WMI : $_"
        }
    }

    if($SccmSessionObject) {
        # return the new session object to the pipeline        
        $SccmSessionObject

        # store the session object in the script store
        $Null = $Script:SccmSessions.add($SccmSessionObject)
    }
}


function Get-SccmSession {
<#
    .SYNOPSIS

        Returns a specified stored PowerSccm.Session object or all
        stored PowerSccm.Session objects.

    .PARAMETER Id

        The Id of a stored Sccm session object created by New-SccmSession.

    .PARAMETER Name

        The Name of a stored Sccm session object created by New-SccmSession,
        wildcards accepted.

    .PARAMETER ComputerName

        The ComputerName of a stored Sccm session object created by New-SccmSession,
        wildcards accepted.

    .PARAMETER SiteCode

        The SiteCode of a stored Sccm session object created by New-SccmSession,
        wildcards accepted.

    .PARAMETER ConnectionType

        The ConnectionType of a stored Sccm session object created by New-SccmSession,
        wildcards accepted.

    .EXAMPLE

        PS C:\> Get-SccmSession

        Return all active Sccm sessions stored.

    .EXAMPLE

        PS C:\> Get-SccmSession -Id 3

        Return the active sessions stored for Id of 3

    .EXAMPLE

        PS C:\> Get-SccmSession -Name LOL1

        Return named LOL1 session.

    .EXAMPLE

        PS C:\> Get-SccmSession -ComputerName SccmSERVER

        Return the active sessions stored for the SccmSERVER machine

    .EXAMPLE

        PS C:\> Get-SccmSession -SiteCode LOL

        Return the active sessions stored sitcode LOL.

    .EXAMPLE

        PS C:\> Get-SccmSession -ConnectionType WMI

        Return active WMI sessions.
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
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
        $ComputerName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        [ValidatePattern('^[A-Za-z]{3}$')]
        $SiteCode,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        [ValidateSet("Database", "DB", "SQL", "WMI")]
        $ConnectionType
    )

    if($PSBoundParameters['Session']) {
        $Session
    }

    elseif($Script:SccmSessions) {

        if($PSBoundParameters['Id']) {
            $Script:SccmSessions.Clone() | Where-Object {
                $_.Id -eq $Id
            }
        }

        elseif($PSBoundParameters['Name']) {
            $Script:SccmSessions.Clone() | Where-Object {
                $_.Name -like $Name
            }
        }

        elseif($PSBoundParameters['ComputerName']) {
            if($PSBoundParameters['SiteCode']) {
                $Script:SccmSessions.Clone() | Where-Object {
                    ($_.ComputerName -like $ComputerName) -and ($_.SiteCode -like $SiteCode)
                }
            }
            else {
                $Script:SccmSessions.Clone() | Where-Object {
                    $_.ComputerName -like $ComputerName
                }
            }
        }

        elseif($PSBoundParameters['SiteCode']) {
            $Script:SccmSessions.Clone() | Where-Object {
                $_.SiteCode -like $SiteCode
            }
        }

        elseif($PSBoundParameters['ConnectionType']) {
            $Script:SccmSessions.Clone() | Where-Object {
                $_.ConnectionType -like $ConnectionType
            }
        }

        else {
            $Script:SccmSessions.Clone()
        }
    }
}


function Remove-SccmSession {
<#
    .SYNOPSIS

        Closes and destroys a Sccm database connection object either passed
        on the pipeline or specified by the Id/Name/ComputerName/SiteCode/ConnectionType.

    .PARAMETER Session

        The custom PowerSccm.Session object generated and stored by New-SccmSession,
        passable on the pipeline.

    .PARAMETER Id

        The Id of a stored Sccm session object created by New-SccmSession.

    .PARAMETER Name

        The Name of a stored Sccm session object created by New-SccmSession,
        wildcards accepted.

    .PARAMETER ComputerName

        The ComputerName of a stored Sccm session object created by New-SccmSession,
        wildcards accepted.

    .PARAMETER SiteCode

        The SiteCode of a stored Sccm session object created by New-SccmSession,
        wildcards accepted.

    .PARAMETER ConnectionType

        The ConnectionType of a stored Sccm session object created by New-SccmSession,
        wildcards accepted.

    .EXAMPLE

        PS C:\> Remove-SccmSession -Id 3

        Destroy/remove the active database sessions stored for Id of 3

    .EXAMPLE

        PS C:\> Remove-SccmSession -Name LOL1

        Destroy/remove the named LOL1 active database session

    .EXAMPLE

        PS C:\> Remove-SccmSession -ComputerName SccmSERVER

        Destroy/remove the active database sessions stored for the SccmSERVER machine

    .EXAMPLE

        PS C:\> Remove-SccmSession -SiteCode LOL

        Destroy/remove the active database sessions stored for sitecode of LOL.

    .EXAMPLE

        PS C:\> Get-SccmSession -Name LOL1 | Remove-SccmSession

        Close/destroy the active database session stored for the LOL1 named session.
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
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
        $ComputerName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        [ValidatePattern('^[A-Za-z]{3}$')]
        $SiteCode,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        [ValidateSet("Database", "DB", "SQL", "WMI")]
        $ConnectionType
    )

    process {
        Get-SccmSession @PSBoundParameters | ForEach-Object {
            Write-Verbose "Removing session '$($_.Name)'"
            if($_.ConnectionType -NotLike "WMI") {
                $_.Provider.Close()
            }
            $Script:SccmSessions.Remove($_)
        }
    }
}


function Invoke-SccmQuery {
<#
    .SYNOPSIS

        Helper that executes a given Sccm SQL or WMI query on the passed Sccm 
        session object.
        Should not normally be called by the user.

    .PARAMETER Session

        The custom PowerSccm.Session object returned by Get-SccmSession, passable on the pipeline.

    .PARAMETER Query

        The Sccm SQL or WMI query to run.
#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $Query
    )

    process {

        if($Query.Trim().StartsWith("-- MIN_Sccm_VERSION")) {
            # if the query specifies a minimum version, make sure this connection complies
            $FirstLine = $($Query -Split "\n")[0]
            $MinVersion = ($FirstLine -Split "=")[1].trim()

            if($MinVersion) {
                if($MinVersion -gt $($Session.SccmVersion)) {
                    Throw "Query requires a minimum Sccm version ($MinVersion) higher than the current connection ($($Session.SccmVersion))!"
                }
            }
        }

        if($Session.ConnectionType -Like "WMI") {

            Write-Verbose "Running WMI query on session $($Session.Name): $Query"
            $Namespace = $($Session.Provider.NamespacePath -split "\\", 4)[3]

            if($Session.Credential) {
                Get-WmiObject -ComputerName $Session.ComputerName -Namespace $Namespace -Query $Query -Credential $Session.Credential
            }
            else {
                Get-WmiObject -ComputerName $Session.ComputerName -Namespace $Namespace -Query $Query
            }
        }
        else {

            Write-Verbose "Running database SQL query on session $($Session.Name): $Query"

            $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($Query, $Session.Provider)

            $Table = New-Object System.Data.DataSet
            $Null = $SqlAdapter.Fill($Table)

            $Table.Tables[0]
        }
    }
}


function Get-SQLQueryFilter {
<#
    .SYNOPSIS

        Helper that takes a -Query SQL string and a set of PSBoundParameters
        and returns the appropriate final query string for a Get-Sccm*
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

    if($Parameters['FilterRaw']) {
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
            if($Value.Contains(" or ")){
                $Values = $Value -split " or " | ForEach-Object {$_.trim()}
            }
            else {
                $Values = @($Value)
            }

            if($Query.Contains("AS DATA")) {
                if($Query.EndsWith("AS DATA")) {
                    $Query += "`nWHERE ("
                }
                else {
                    $Query += "`nAND ("
                }
            }
            elseif($Query.Contains("WHERE")) {
                $Query += "`nAND ("
            }
            else {
                $Query += "`nWHERE ("
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


function Get-WMIQueryFilter {
<#
    .SYNOPSIS

        Helper that takes a -Query WMI string and a set of PSBoundParameters
        and returns the appropriate final query string for a Get-Sccm*
        function based on the given filter options.

    .PARAMETER Query

        The multi-line WMI query string to append logic to.

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

        $Query += "`nWHERE ($Filter)"
    }
    else {

        $Parameters.GetEnumerator() | Where-Object {($_.Key -like '*Filter') -and ($_.Key -ne 'Filter')} | ForEach-Object {

            # get the SQL wildcards correct
            $Value = $_.Value.Replace('*', '%')

            # if we have multiple values to build clauses for
            if($Value.Contains(" or ")){
                $Values = $Value -split " or " | ForEach-Object {$_.trim()}
            }
            else {
                $Values = @($Value)
            }

            $Query += "`nWHERE ("

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

    $Query
}


##############################################
#
# Functions that query or modified information
# in the Sccm database/server itself (as opposed) to
# client information in the Sccm database).
#
##############################################

function Find-SccmSiteCode {
<#
    .SYNOPSIS

        Takes a given Sccm server and returns available site names.

    .PARAMETER ComputerName

        The name key of an Sccm database to create a temporary connection to for
        the query.

    .PARAMETER ConnectionType

        The method to connect to the remote Sccm server. 'WMI' uses a WMI connection and the
        Sccm SMS_ WMI classes. 'Database'/'DB'/'SQL' connects to the Sccm MSSQL backend database.
        Default to WMI.

    .PARAMETER Credential

        A [Management.Automation.PSCredential] object that stores a SqlUserName and SqlPassword
        or a domain credential to use for WMI connections.

    .PARAMETER SqlUserName

        Specific MSSQL username to use instead of integrated Windows authentication.

    .PARAMETER SqlPassword

        Specific MSSQL username to use instead of integrated Windows authentication.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerName,

        [Parameter(Position = 1)]
        [String]
        [ValidateSet("Database", "DB", "SQL", "WMI")]
        $ConnectionType = "SQL",

        [Parameter(Position = 2)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(ParameterSetName = 'SQLCredentials', Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $SqlUserName,

        [Parameter(ParameterSetName = 'SQLCredentials', Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $SqlPassword
    )

    process {
        if($ConnectionType -like "WMI") {

            $Query = "SELECT * FROM SMS_ProviderLocation where ProviderForLocalSite = true"

            if($Session.Credential) {
                Get-WmiObject -ComputerName $ComputerName -Namespace "root\sms" -Query $Query -Credential $Session.Credential | ForEach-Object {New-Object PSObject -Property @{'SiteCode' = $_.SiteCode}}
            }
            else {
                Get-WmiObject -ComputerName $ComputerName -Namespace "root\sms" -Query $Query | ForEach-Object {New-Object PSObject -Property @{'SiteCode' = $_.SiteCode}}
            }
        }
        else {
            try {
                # ...yes I know this is duplicate logic MATT :)
                #   this seemed to be the easiest way to preserve the functionality
                #   of New-SccmSession without major modification
                $SQLConnection = New-Object System.Data.SQLClient.SQLConnection

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

                $Query = "SELECT name FROM Sys.Databases WHERE name LIKE 'CM_%' AND state_desc = 'ONLINE'"
                $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($Query, $SQLConnection)

                $Table = New-Object System.Data.DataSet
                $Null = $SqlAdapter.Fill($Table)

                $Table.Tables[0] | ForEach-Object {
                    
                    New-Object PSObject -Property @{'SiteCode' = $($_[0] -split "_")[1]}
                } 

                $SQLConnection.Close()
            }
            catch {
                Write-Error "Error enumerating SQL database on server '$ComputerName' : $_"
            }
        }
    }
}


function Get-SccmApplicationCI {
<#
    .SYNOPSIS

        Returns applications that exist on the primary site server.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
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

        PS C:\> Get-SccmSession | Get-SccmApplicationCI

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmApplicationCI -FilterName IsHidden -FilterValue 1

        Finds all hidden user deployed application configuration items.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
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

        $SqlQuery = @"
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

        $WMIQuery = "SELECT * FROM SMS_Application"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmPackage {
<#
    .SYNOPSIS

        Returns Sccm packages that exist on the primary site server.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
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

        PS C:\> Get-SccmSession | Get-SccmPackage

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmPackage -Verbose -SourcePathFilter '\\PRIMARY.testlab.local\*'

        Returns packaged with a source location on \\PRIMARY.testlab.local\
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
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

        $SqlQuery = @"
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

        $WMIQuery = "SELECT * FROM SMS_Package"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmConfigurationItem {
<#
    .SYNOPSIS

        Returns Sccm configuration items that exist on the primary site server.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmConfigurationItem -CI_IDFilter 12345

        Returns the configuration item with ID 12345

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmConfigurationItem -IsHiddenFilter 1 -IsUserDefinedFilter 1

        Returns the all user defined configuration items that are marked as hidden.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
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

        $SqlQuery = @"
SELECT TOP $Newest
    * from CI_ConfigurationItems QUERY
WHERE
     CI_ID is not null
"@

        $WMIQuery = "SELECT * FROM SMS_ConfigurationItem"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Set-SccmConfigurationItem {
<#
    .SYNOPSIS

        Sets a field to a particular value for a Sccm configuration keyed by CI_ID.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER CI_ID

        The configuration interface ID of the application to manipulate.
        You can retrieve this with Get-SccmApplication or Get-SccmConfigurationItem.

    .PARAMETER Column

        The column/field name to set.

    .PARAMETER Value

        Value to set the Field to.

    .EXAMPLE

        PS C:\> Get-SccmSession | Set-SccmConfigurationItem -CI_ID 12345 -Field IsHidden -Value 1

        Set the configuration item with If 12345 to be hidden from the Sccm GUi.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
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
        
        if($Session.ConnectionType -like 'WMI') {
            throw "WMI functionality for Set-SccmConfigurationItem not yet implemented in PowerSCCM"
        }

        Invoke-SccmQuery -Session $Session -Query $Query
    }
}


function Get-SccmCollection {
<#
    .SYNOPSIS

        Returns Sccm collections that exist on the primary site server.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmPackage

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmPackage -Verbose -SourcePathFilter '\\PRIMARY.testlab.local\*'

        Returns packaged with a source location on \\PRIMARY.testlab.local\
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [String]
        [ValidateSet("CollectionID","SiteID","CollectionName","CollectionComment","IsBuiltIn","MemberCount","Flags","Schedule","LastChangeTime","LastRefreshTime","BeginDate","EvaluationStartTime","LastMemberChangeTime","RefreshType","CollectionType","CurrentStatus","ResultTableName")]
        $OrderBy,

        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $CollectionIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SiteIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CollectionNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CollectionCommentFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $IsBuiltInFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $MemberCountFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $FlagsFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ScheduleFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $LastChangeTimeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $LastRefreshTimeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $BeginDateFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $EvaluationStartTimeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $LastMemberChangeTimeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $RefreshTypeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CollectionTypeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CurrentStatusFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ResultTableNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $SqlQuery = @"
SELECT TOP $Newest
      CollectionID,
      SiteID,
      CollectionName,
      CollectionComment,
      IsBuiltIn,
      MemberCount,
      Flags,
      Schedule,
      LastChangeTime,
      LastRefreshTime,
      BeginDate,
      EvaluationStartTime,
      LastMemberChangeTime,
      RefreshType,
      CollectionType,
      CurrentStatus,
      ResultTableName
FROM 
    vCollections
"@

        $WMIQuery = "SELECT * FROM SMS_Collection"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmCollectionMember {
<#
    .SYNOPSIS

        Returns Sccm collection members.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER Filter

        Raw filter to build a WHERE clause instead of -XFilter options.
        Form of "ComputerName like '%WINDOWS%' OR Name like '%malicious%'"

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmPackage

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmPackage -Verbose -SourcePathFilter '\\PRIMARY.testlab.local\*'

        Returns packaged with a source location on \\PRIMARY.testlab.local\
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [String]
        [ValidateSet("CollectionID","SiteID","MachineID","ArchitectureKey","Name","Domain","SMSID","SiteCode","IsDirect","IsAssigned","IsClient")]
        $OrderBy,

        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $CollectionIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SiteIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $MachineIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ArchitectureKeyFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DomainFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SMSIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SiteCodeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $IsDirectFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $IsAssignedFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $IsClientFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $SqlQuery = @"
SELECT TOP $Newest
    CollectionID,
    SiteID,
    MachineID,
    ArchitectureKey,
    Name,
    Domain,
    SMSID,
    SiteCode,
    IsDirect,
    IsAssigned,
    IsClient
FROM 
    vCollectionMembers
"@

        $WMIQuery = "SELECT * FROM SMS_CollectionMember"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}

##############################################
#
# Common defensive queries involving information
# collected from client machines.
#
##############################################

function Get-SccmService {
<#
    .SYNOPSIS

        Returns information on the current set of running services as of the
        last Sccm agent query/checkin.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SccmTimeStampFilter

        Query only for results where the Sccm TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SccmTimeStampFilter '>2012-03-01 00:00:00.000')

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

        PS C:\> $Session = Get-SccmSession
        PS C:\> Get-SccmService -Session $Session

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmService -ComputerFilterName WINDOWS1

        Returns service information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmService -ComputerFilterName WINDOWS* -Newest 10 -OrderBy DisplayName -Descending

        Return the top 10 services for system matching the computer name WINDOWS*, ordered by
        descending DisplayName

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmService -PathNameFilter "C:\Temp\* or C:\Malicious\*"

        Returns services with a path name starting with C:\Temp\ or C:\Malicious\
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SccmTimeStamp", "Caption","Description","DisplayName", "ErrorControl", "ExitCode", "Name", "PathName", "ProcessId", "ServiceType", "Started", "StartMode", "State")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SccmTimeStampFilter,

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

        $SqlQuery = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SccmTimeStamp,
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

        $WMIQuery = "SELECT * FROM SMS_G_System_SERVICE"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmServiceHistory {
<#
    .SYNOPSIS

        Returns information on the historical set of running services as of the
        last Sccm agent query/checkin.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SccmTimeStampFilter

        Query only for results where the Sccm TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SccmTimeStampFilter '>2012-03-01 00:00:00.000')

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

        PS C:\> Get-SccmSession | Get-SccmServiceHistory

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmServiceHistory -ComputerFilterName WINDOWS1

        Returns historical service information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmServiceHistory -ComputerFilterName WINDOWS* -Newest 10 -OrderBy DisplayName -Descending

        Return the top 10 historical services for system matching the computer name WINDOWS*, ordered by
        descending DisplayName
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SccmTimestamp", "Caption","Description","DisplayName", "ErrorControl", "ExitCode", "Name", "PathName", "ProcessId", "ServiceType", "Started", "StartMode", "State")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SccmTimeStampFilter,

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
         QUERY.TimeStamp as SccmTimeStamp,
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
        $Query = Get-SQLQueryFilter -Query $Query -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            throw "WMI functionality for Get-SccmServiceHistory is not implemented."
        }
        Invoke-SccmQuery -Session $Session -Query $Query
    }
}


function Get-SccmAutoStart {
<#
    .SYNOPSIS

        Returns information on the set of autostart programs as of the
        last Sccm agent query/checkin.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SccmTimeStampFilter

        Query only for results where the Sccm TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SccmTimeStampFilter '>2012-03-01 00:00:00.000')

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

        PS C:\> Get-SccmSession | Get-SccmAutoStart

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmAutoStart -ComputerFilterName WINDOWS1

        Returns autostate information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmAutoStart -DescriptionFilter *malicious*

        Returns autostate information for entries with *malicious* in the description.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SccmTimestamp", "Description", "FileName", "FileVersion", "Location", "Product", "Publisher", "StartupType", "StartupValue")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SccmTimeStampFilter,

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

        $SqlQuery = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SccmTimeStamp,
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

        $WMIQuery = "SELECT * FROM SMS_G_System_AUTOSTART_SOFTWARE"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmProcess {
<#
    .SYNOPSIS

        Returns information on the set of currently running processes as of the
        last Sccm agent query/checkin.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SccmTimeStampFilter

        Query only for results where the Sccm TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SccmTimeStampFilter '>2012-03-01 00:00:00.000')

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

        PS C:\> Get-SccmSession | Get-SccmProcess

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmProcess -ComputerFilterName WINDOWS1

        Returns process information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmProcess -NameFilter *malicious*

        Returns process information for any process with *malicious* in the name.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SccmTimestamp", "Caption", "CreationDate", "Description", "ExecutablePath", "Name", "ParentProcessId", "ProcessId")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SccmTimeStampFilter,

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

        $SqlQuery = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SccmTimeStamp,
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

        $WMIQuery = "SELECT * FROM SMS_G_System_PROCESS"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmProcessHistory {
<#
    .SYNOPSIS

        Returns information on the historical set of running processes as of the
        last Sccm agent query/checkin.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SccmTimeStampFilter

        Query only for results where the Sccm TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SccmTimeStampFilter '>2012-03-01 00:00:00.000')

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

        PS C:\> Get-SccmSession | Get-SccmProcessHistory

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmProcessHistory -ComputerFilterName WINDOWS1

        Returns historical process information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmProcessHistory -NameFilter *malicious*

        Returns historical process information for any process with *malicious* in the name.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SccmTimestamp", "Caption", "CreationDate", "Description", "ExecutablePath", "Name", "ParentProcessId", "ProcessId")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SccmTimeStampFilter,

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
         QUERY.TimeStamp as SccmTimeStamp,
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
        $Query = Get-SQLQueryFilter -Query $Query -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            throw "WMI functionality for Get-SccmServiceHistory is not implemented."
        }
        Invoke-SccmQuery -Session $Session -Query $Query
    }
}


function Get-SccmRecentlyUsedApplication {
<#
    .SYNOPSIS

        Returns information on the set of recently used applications as of the
        last Sccm agent query/checkin.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SccmTimeStampFilter

        Query only for results where the Sccm TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SccmTimeStampFilter '>2012-03-01 00:00:00.000')

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

        PS C:\> Get-SccmSession | Get-SccmRecentlyUsedApplication

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmRecentlyUsedApplication -ComputerFilterName WINDOWS1

        Returns recently used applications just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmRecentlyUsedApplication -FileDescriptionFilter *mimikatz*

        Returns recently used applications with *mimikatz* in the description.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SccmTimestamp", "CompanyName", "ExplorerFileName", "FileDescription", "FileSize", "FileVersion", "FolderPath", "LastUsedTime", "LastUserName", "OriginalFileName", "ProductName", "ProductVersion")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SccmTimeStampFilter,

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

        $SqlQuery = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SccmTimeStamp,
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

        $WMIQuery = "SELECT * FROM SMS_G_System_CCM_RECENTLY_USED_APPS"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmDriver {
<#
    .SYNOPSIS

        Returns information on the set of currently loaded system drivers as of the
        last Sccm agent query/checkin.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SccmTimeStampFilter

        Query only for results where the Sccm TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SccmTimeStampFilter '>2012-03-01 00:00:00.000')

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

        PS C:\> Get-SccmSession | Get-SccmDriver

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmDriver -ComputerFilterName WINDOWS1

        Returns driver information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmDriver -PathNameFilter C:\Temp\*

        Returns information on all drivers located in C:\Temp\
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SccmTimestamp", "Caption", "Description", "DisplayName", "ErrorControl", "ExitCode", "Name", "PathName", "ServiceType", "StartMode", "State")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SccmTimeStampFilter,

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

        $SqlQuery = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SccmTimeStamp,
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

        $WMIQuery = "SELECT * FROM SMS_G_System_SYSTEM_DRIVER"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmConsoleUsage {
<#
    .SYNOPSIS

        Returns historical information on user console usage as of the
        last Sccm agent query/checkin.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SccmTimeStampFilter

        Query only for results where the Sccm TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SccmTimeStampFilter '>2012-03-01 00:00:00.000')

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

        PS C:\> Get-SccmSession | Get-SccmConsoleUsage

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmConsoleUsage -ComputerFilterName WINDOWS1

        Returns console usage information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmConsoleUsage -SystemConsoleUserFilter DOMAIN\john

        Returns console usage information for the user 'DOMAIN\john' from all inventoried machines.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SccmTimestamp", "SystemConsoleUser", "LastConsoleUse", "NumberOfConsoleLogons", "TotalUserConsoleMinutes")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SccmTimeStampFilter,

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

        $SqlQuery = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SccmTimeStamp,
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

        # TODO: link with ResourceId in SMS_G_System_COMPUTER_SYSTEM class to get computer name
        $WMIQuery = "SELECT * FROM SMS_G_System_SYSTEM_CONSOLE_USER"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmSoftwareFile {
<#
    .SYNOPSIS

        Returns information on inventoried non-Microsoft software files.
        This option is not enabled by default in Sccm- we recommend setting Sccm
        to inventory all *.exe files on hosts.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
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

        PS C:\> Get-SccmSession | Get-SccmSoftwareFile

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmSoftwareFile -ComputerFilterName WINDOWS1

        Returns software file information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmSoftwareFile -FilePathFilter C:\Temp\*

        Returns information on software files located in C:\Temp\
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
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

        $SqlQuery = @"
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

        # TODO: link with ResourceId in SMS_G_System_COMPUTER_SYSTEM class to get computer name
        $WMIQuery = "SELECT * FROM SMS_G_System_SoftwareFile"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmBrowserHelperObject {
<#
    .SYNOPSIS

        Returns information on discovered browser helper objects.
        This option is not enabled by default.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SccmTimeStampFilter

        Query only for results where the Sccm TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SccmTimeStampFilter '>2012-03-01 00:00:00.000')

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

        PS C:\> Get-SccmSession | Get-SccmBrowserHelperObject

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmBrowserHelperObject -ComputerFilterName WINDOWS1

        Returns browser helper object information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmBrowserHelperObject -DescriptionFilter *malicious*

        Returns browser helper object information with a wildcard match for *malicious* in the description field.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SccmTimestamp", "BinFileVersion", "BinProductVersion", "Description", "FileName", "FileVersion", "Product", "ProductVersion", "Publisher", "Version")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SccmTimeStampFilter,

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

        $SqlQuery = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SccmTimeStamp,
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

        $WMIQuery = "SELECT * FROM SMS_G_System_BROWSER_HELPER_OBJECT"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmShare {
<#
    .SYNOPSIS

        Returns information on discovered shares.
        This option is not enabled by default.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER ComputerNameFilter

        Query only for results where the ComputerName field matches the given filter.
        Wildcards accepted.

    .PARAMETER SccmTimeStampFilter

        Query only for results where the Sccm TimeStamp field matches the given filter.
        <> operators accepted (e.g. -SccmTimeStampFilter '>2012-03-01 00:00:00.000')

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

        PS C:\> Get-SccmSession | Get-SccmShare

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmShare -ComputerFilterName WINDOWS1

        Returns share information just for the WINDOWS1 client.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmShare -DescriptionFilter *secret*

        Returns share information with a wildcard match for *secret* in the description field.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("SccmTimestamp", "Caption", "Description", "Name", "Path")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SccmTimeStampFilter,

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

        $SqlQuery = @"
SELECT * FROM
(
    SELECT TOP $Newest
         COMPUTER.ResourceID as ResourceID,
         COMPUTER.Name0 as ComputerName,
         ADAPTER.IPAddress0 as IPAddress,
         QUERY.TimeStamp as SccmTimeStamp,
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

        $WMIQuery = "SELECT * FROM SMS_G_System_SHARE"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmPrimaryUser {
<#
    .SYNOPSIS

        Returns information on primary users set for specific machine names.
        This option is not enabled by default.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
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

        PS C:\> Get-SccmSession | Get-SccmPrimaryUser

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmPrimaryUser -ComputerFilterName WINDOWS1

        Returns primary user information for just the WINDOWS1 machine.

    .EXAMPLE

        PS C:\> Get-SccmPrimaryUser | Get-SccmPrimaryUser -Unique_User_NameFilter "DOMAIN\will"

        Returns the locations where DOMAIN\Will is a primary user
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
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

        $SqlQuery = @"
-- MIN_Sccm_VERSION = 5
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

        $WMIQuery = "SELECT * FROM SMS_UserMachineRelationship"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


##############################################
#
# Common meta-queries to search for 'bad' things
# from information collected from client machines.
#
##############################################

function Find-SccmRenamedCMD {
<#
    .SYNOPSIS

        Finds renamed cmd.exe executables using Get-SccmRecentlyUsedApplication
        and appropriate filters.

        Adapted from slide 16 in John McLeod and Mike-Pilkington's
        "Mining for Evil" presentation.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SccmSession | Find-SccmRenamedCMD
        
        Runs the query against all current Sccm sessions.

    .LINK

        https://digital-forensics.sans.org/summit-archives/DFIR_Summit/Mining-for-Evil-John-McLeod-Mike-Pilkington.pdf
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session
    )

    process {
        # find recently launched executables in C:\ with 'Windows Command Processor' as the Description
        #   and a name not like cmd.exe
        Get-SccmRecentlyUsedApplication -Session $Session -FolderPathFilter "C:\*" -FileDescriptionFilter 'Windows Command Processor' -ExplorerFileNameFilter "!cmd.exe"
    }
}


function Find-SccmUnusualEXE {
<#
    .SYNOPSIS

        Finds recently launched applications that don't end in *.exe using
        Get-SccmRecentlyUsedApplication and appropriate filters.

        Adapted from slide 18 in John McLeod and Mike-Pilkington's
        "Mining for Evil" presentation.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SccmSession | Find-SccmUnusualEXE

        Runs the query against all current Sccm sessions.

    .LINK

        https://digital-forensics.sans.org/summit-archives/DFIR_Summit/Mining-for-Evil-John-McLeod-Mike-Pilkington.pdf
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session
    )

    process {
        # find recently launched executables in C:\ that don't end in *.exe
        Get-SccmRecentlyUsedApplication -Session $Session -FolderPathFilter "C:\*" -ExplorerFileNameFilter "!*.exe"
    }
}


function Find-SccmRareApplication {
<#
    .SYNOPSIS

        Finds the rarest -Limit <X> recently launched applications that don't end in *.exe using
        Get-SccmRecentlyUsedApplication and appropriate filters.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Limit

        The limit of number of rarest applications to return. Default of 100.

    .EXAMPLE

        PS C:\> Get-SccmSession | Find-SccmRareApplication -Limit 10

        Finds the 10 rarest launched applications.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        [ValidateNotNullOrEmpty()]
        $Limit = 100
    )

    process {
        # find all recently used applications, group by the launched ExplorerFileName,
        #   sort by the count and return the top -Limit <X> number
        Get-SccmRecentlyUsedApplication -Session $Session | Group-Object -Property ExplorerFileName | Sort-Object -Property Count | Select-Object -First $Limit
    }
}


function Find-SccmPostExploitation {
<#
    .SYNOPSIS

        Finds recently launched applications commonly used in post-exploitation.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SccmSession | Find-SccmPostExploitation

        Runs the query against all current Sccm sessions.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session
    )

    process {
        # common post-exploitation tool names to search for in recently launched applications
        $PostExTools = "net.exe", "whoami.exe", "runas.exe", "rdpclip.exe", "at.exe", "schtasks.exe", "wmic.exe", "tasklist.exe", "sc.exe", "psexec.exe", "hostname.exe", "ver.exe", "dsquery.exe", "reg.exe", "*nmap*", "*mimikatz*", "*wce*", "*fgdump*", "*cain*", "*abel*", "*superscan*"
        Get-SccmRecentlyUsedApplication -Session $Session -ExplorerFileNameFilter $($PostExTools -join " or ")
    }
}


function Find-SccmPostExploitationFile {
<#
    .SYNOPSIS

        Finds indexed .exe's commonly used in post-exploitation.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SccmSession | Find-SccmPostExploitationFile

        Runs the query against all current Sccm sessions.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session
    )

    process {
        # common post-exploitation tool names to search for in inventoried files
        $PostExTools = "net.exe", "whoami.exe", "runas.exe", "rdpclip.exe", "at.exe", "schtasks.exe", "wmic.exe", "tasklist.exe", "sc.exe", "psexec.exe", "hostname.exe", "ver.exe", "dsquery.exe", "reg.exe", "*nmap*", "*mimikatz*", "*wce*", "*fgdump*", "*cain*", "*abel*", "*superscan*"

        Get-SccmSoftwareFile -Session $Session -FileNameFilter $($PostExTools -join " or ")
    }
}


function Find-SccmMimikatz {
<#
    .SYNOPSIS

        Finds launched mimikatz instances by searching the 'FileDescription' and 'CompanyName' fields of recently launched applications.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SccmSession | Find-SccmMimikatz

        Runs the query against all current Sccm sessions.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session
    )

    process {
        Get-SccmRecentlyUsedApplication -Session $Session -Filter "(CompanyName LIKE '%gentilkiwi%') OR (FileDescription LIKE '%mimikatz%')"
    }
}


function Find-SccmMimikatzFile {
<#
    .SYNOPSIS

        Finds inventoried mimikatz.exe instances by searching the 'FileDescription'
        field of inventoried .exe's.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-SccmSession | Find-SccmMimikatzFile

        Runs the query against all current Sccm sessions.
#>
    [CmdletBinding()]
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session
    )

    process {
        Get-SccmSoftwareFile -Session $Session -FileDescriptionFilter "*mimikatz*"
    }
}


##############################################
#
# Active Directory related cmdlets
#
##############################################

function Get-SccmADForest {
<#
    .SYNOPSIS

        Returns information on Active Directory forests enumerated
        by Sccm agents.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER Filter

        Raw filter to build a WHERE clause. Form of "Description like '%testlab%'""

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmADForest

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmADForest -DescriptionFilter "*testlab*"

        Returns information on forests with 'testlab' in the description.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmADForest -Filter "Description like '%testlab%'"

        Returns information on forests with 'testlab' in the description.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("CreatedOn", "Description", "DiscoveryEnabled", "ForestFQDN", "ForestID", "ModifiedBy", "ModifiedOn", "PublishingEnabled", "PublishingPath", "Tombstoned", "LastDiscoveryTime", "Account", "LastDiscoveryStatus", "PublishingStatus", "DiscoveredTrusts", "DiscoveredDomains", "DiscoveredADSites", "DiscoveredIPSubnets")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $CreatedByFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $CreatedOnFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DescriptionFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DiscoveryEnabledFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ForestFQDNFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ForestIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ModifiedByFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ModifiedOnFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $LastDiscoveryTimeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DiscoveredTrustsFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DiscoveredDomainsFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DiscoveredADSitesFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $DiscoveredIPSubnetsFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $SqlQuery = @"
SELECT TOP $Newest
    ForestFQDN,
    Description,
    ForestID,
    CreatedBy,
    CreatedOn,
    DiscoveryEnabled,
    ModifiedBy,
    ModifiedOn,
    PublishingEnabled,
    PublishingPath,
    Tombstoned,
    LastDiscoveryTime,
    Account,
    LastDiscoveryStatus,
    PublishingStatus,
    DiscoveredTrusts,
    DiscoveredDomains,
    DiscoveredADSites,
    DiscoveredIPSubnets
FROM
    vActiveDirectoryForests
"@

        $WMIQuery = "SELECT * FROM SMS_ADForest"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmADUser {
<#
    .SYNOPSIS

        Returns information on Active Directory users enumerated
        by Sccm agents.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER Filter

        Raw filter to build a WHERE clause. Form of "Description like '%testlab%'""

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmADUser

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmADUser -Distinguished_Name '*will*'

        Returns information on groups with 'will' in the distinguished name.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("ResourceId", "ResourceType", "CloudUserId", "Creation_Date", "Distinguished_Name", "Full_Domain_Name", "Full_User_Name", "Mail", "Name", "Network_Operating_System", "Object_GUID", "Primary_Group_ID", "SID", "Unique_User_Name", "User_Account_Control", "User_Name", "User_Principal_Name", "Windows_NT_Domain")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $ResourceIdFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $User_NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $User_Principal_NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Distinguished_NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Full_Domain_NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Primary_Group_IDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $User_Account_ControlFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Creation_DateFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $MailFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $SqlQuery = @"
SELECT * FROM
(    
    SELECT TOP $Newest
        Name0 AS Name,
        User_Name0 AS User_Name,
        User_Principal_Name0 AS User_Principal_Name,
        Distinguished_Name0 AS Distinguished_Name,
        Full_User_Name0 AS Full_User_Name,
        Full_Domain_Name0 AS Full_Domain_Name,
        Windows_NT_Domain0 AS Windows_NT_Domain,
        SID0 AS SID,
        Primary_Group_ID0 AS Primary_Group_ID,
        Unique_User_Name0 AS Unique_User_Name,
        User_Account_Control0 AS User_Account_Control,
        ResourceID,
        ResourceType,
        CloudUserId,
        Creation_Date0 AS Creation_Date,
        Mail0 AS Mail,
        Network_Operating_System0 AS Network_Operating_System,
        Object_GUID0 AS Object_GUID
    FROM
         v_R_User
)
    AS DATA
"@

        $WMIQuery = "SELECT * FROM SMS_R_User"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmADGroup {
<#
    .SYNOPSIS

        Returns information on Active Directory group enumerated
        by Sccm agents.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER Filter

        Raw filter to build a WHERE clause. Form of "Description like '%testlab%'""

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmADGroup

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmADGroup -NameFilter "*Domain Controllers*"

        Returns information on groups with 'Domain Controllers' in the name.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("Name", "Usergroup_Name", "AD_Domain_Name", "Windows_NT_Domain", "Full_Domain_Name", "Full_User_Name", "Mail", "Name", "Network_Operating_System", "SID", "Unique_Usergroup_Name", "ResourceID", "ResourceType", "Creation_Date", "Group_Type")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Usergroup_NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $AD_Domain_NameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $SIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ResourceIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $ResourceTypeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Creation_DateFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Group_TypeFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $SqlQuery = @"
SELECT * FROM
(    
    SELECT TOP $Newest
        Name0 AS Name,
        Usergroup_Name0 AS Usergroup_Name,
        AD_Domain_Name0 AS AD_Domain_Name,
        Windows_NT_Domain0 AS Windows_NT_Domain,
        SID0 AS SID,
        Unique_Usergroup_Name0 AS Unique_Usergroup_Name,
        ResourceID,
        ResourceType,
        Creation_Date0 AS Creation_Date,
        Group_Type0 AS Group_Type,
        Network_Operating_System0 AS Network_Operating_System,
        Object_GUID0 AS Object_GUID
    FROM
         v_R_UserGroup
)
    AS DATA
"@

        $WMIQuery = "SELECT * FROM SMS_R_UserGroup"
        
        # add in our filter logic
        $SqlQuery = Get-SQLQueryFilter -Query $SqlQuery -Parameters $PSBoundParameters
        $WMIQuery = Get-WMIQueryFilter -Query $WMIQuery -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            if($PSBoundParameters['Newest']) {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery | Select-Object -First $Newest
            }
            else {
                Invoke-SccmQuery -Session $Session -Query $WmiQuery
            }
        }
        else {
            Invoke-SccmQuery -Session $Session -Query $SqlQuery
        }
    }
}


function Get-SccmADGroupMember {
<#
    .SYNOPSIS

        Returns information on Active Directory group membership enumerated
        by Sccm agents.

    .PARAMETER Session

        The custom PowerSccm.Session object to query, generated/stored by New-SccmSession
        and retrievable with Get-SccmSession. Required. Passable on the pipeline.

    .PARAMETER Newest

        Restrict the underlying Sccm SQL query to only return the -Newest <X> number of results.
        Detaults to the max value of a 32-bit integer (2147483647).

    .PARAMETER OrderBy

        Order the results by a particular field.

    .PARAMETER Descending

        Switch. If -OrderBy <X> is specified, -Descending will sort the results by
        the given field in descending order.

    .PARAMETER Filter

        Raw filter to build a WHERE clause. Form of "Description like '%testlab%'""

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmADGroup

        Runs the query against all current Sccm sessions.

    .EXAMPLE

        PS C:\> Get-SccmSession | Get-SccmADGroup -NameFilter "*Domain Controllers*"

        Returns information on groups with 'Domain Controllers' in the name.
#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateScript({ $_.PSObject.TypeNames -contains 'PowerSccm.Session'})]
        $Session,

        [Int]
        $Newest = [Int32]::MaxValue,

        [Parameter(Mandatory=$True, ParameterSetName = 'OrderBy')]
        [String]
        [ValidateSet("UserName", "GroupName", "UserResourceID")]
        $OrderBy,

        [Parameter(ParameterSetName = 'OrderBy')]
        [Switch]
        $Descending,

        [String]
        [ValidateNotNullOrEmpty()]
        $UserNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $GroupNameFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $UserResourceIDFilter,

        [String]
        [ValidateNotNullOrEmpty()]
        $Filter
    )

    begin {

        $Query = @"
SELECT * FROM
(
    SELECT TOP $Newest
        G.User_Group_Name0 as GroupName,
        U.User_Principal_Name0 as UserName,
        G.ItemKey as UserResourceID
    FROM
        User_User_Group_Name_ARR G
    JOIN 
        v_R_User U ON G.ItemKey = U.ResourceID
    WHERE
        U.User_Principal_Name0 <> ''
)
    AS DATA
"@

        # add in our filter logic
        $Query = Get-SQLQueryFilter -Query $Query -Parameters $PSBoundParameters
    }

    process {
        if($Session.ConnectionType -like 'WMI') {
            throw "WMI functionality for Get-SccmServiceHistory is not implemented."
        }
        Invoke-SccmQuery -Session $Session -Query $Query
    }
}
