<#
    .SYNOPSIS 
      RibbonSBCEdge Powershell module allows access to Ribbon SBC Edge via PowerShell using REST API's.
	 
	.DESCRIPTION
	  
	  For the module to run correctly following pre-requisites should be met:
	  1) PowerShell v4.0
	  2) Ribbon SBC Edge on R3.0 or higher ( Tested on SBC R8.0 )
	  3) Create REST logon credentials (http://www.allthingsuc.co.uk/accessing-sonus-ux-with-rest-apis/)
    
      Once you have created the account use help Connect-UxGateway to get started.
	 
	.NOTES
		Name: RibbonEdge
        V2 Author: Chris Burns (GCIcom)
        V1 Author: Vikas Jaswal (Modality Systems Ltd)
		Additional cmdlets added by: Kjetil Lindløkken
        Additional cmdlets added by: Adrien Plessis
        
		
		Version History:
        Version 2.1 - 25/04/19 - Updated with some more Get and New Commands especially Call Routing Table - Chris Burns
        Version 2.0 - 15/04/19 - *NEW Version* - Rewrite for modern module design, better use of [XML] accelerator and details switch,
                                 a new custom uxSession Object to allow for access to multiple SBC's at once and a Custom XML -> PSObject Parser - Chris Burns
        
		Version 1.7 - 20/12/18 - Match Ribbon rebranding, Update link to Ribbon Docs - Adrien Plessis
        Version 1.6 - 04/10/18 - Added new-uxsipprofile cmdlet - Kjetil Lindløkken
        Version 1.5 - 03/10/18 - Added optional parameter to the get-uxsipprofile cmdlet to add id directly - Kjetil Lindløkken
        Version 1.4 - 03/10/18 - Added new-uxsipserverentry cmdlet - Kjetil Lindløkken
        Version 1.3 - 02/10/18 - Added get-uxsipprofile, Get-uxsipprofileid, get-uxsipservertableentry cmdlets - Kjetil Lindløkken
        Version 1.2 - 02/10/16 - Added get-uxsipservertable, new-uxsippservertable cmdlets - Kjetil Lindløkken
        Version 1.1 - 03/12/13 - Added new-ux*, restart-ux*, and get-uxresource cmdlets - Vikas Jaswal
        Version 1.0 - 30/11/13 - Module Created - Vikas Jaswal
        
		
		Please use the script at your own risk!
	
    .LINK
        http://www.posh.dev
		http://www.allthingsuc.co.uk
     
  #>



Function Connect-UxGateway {
    <#
	.SYNOPSIS      
	 This cmdlet connects to the Ribbon SBC and extracts the session token and places it into a custom PS Object called uxSession
	 
	.DESCRIPTION
    This cmdlet connects to the Ribbon SBC and extracts the session token required for subsequent cmdlets.
    All other cmdlets will fail if this command is not successfully executed.
	
	.PARAMETER uxhostname
	Enter here the hostname or IP address of the Ribbon SBC
	
	.PARAMETER credentials
	Pass a secure credential to the cmdlet, this should be your REST API credentials.
	
	
	.EXAMPLE
	$Creds = Get-credential
	connect-uxgateway -uxhostname 1.1.1.1 -Credentials $Creds
	
	.EXAMPLE
	$Creds = Get-credential
	connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds

    .EXAMPLE
	$Creds = Get-credential
    $Session1 = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
    $Session2 = connect-uxgateway -uxhostname lyncsbc02.COMPANY.co.uk -Credentials $Creds
	
	#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$uxhostname,
        # The Rest API Credentials to get into the SBC
        [Parameter(Mandatory = $true, Position = 1)]
        [pscredential]$Credentials
    )
	
    if (!($TrustAllCertsPolicy)) {
        #Ignore SSL, without this GET commands dont work with SBC Edge
        add-type @"
	using System.Net;
	using System.Security.Cryptography.X509Certificates;
	public class TrustAllCertsPolicy : ICertificatePolicy {
		public bool CheckValidationResult(
			ServicePoint srvPoint, X509Certificate certificate,
			WebRequest request, int certificateProblem) {
			return true;
		}
	}
"@

        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        #Force TLS1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		
    }
    $null = $Session

    #Login to SBC Edge
    $AuthenticationString = "Username={0}&Password={1}" -f $Credentials.GetNetworkCredential().username, $Credentials.GetNetworkCredential().password
    $url = "https://$uxhostname/rest/login"
	
    Try {
        $uxcommand1output = Invoke-RestMethod -Uri $url -Method Post -Body $AuthenticationString -SessionVariable Session -ErrorAction Stop
    }
    Catch {
        throw "$uxhostname - Unable to connect to $uxhostname. Verify $uxhostname is accessible on the network. The error message returned is $_"
    }
    $Result = ([xml]$uxcommand1output.trim()).root
    $Success = $Result.status.http_code
    Write-verbose "Response Code = $Success"
	
	
    #Check if the Login was successfull.HTTP code 200 is returned if login is successful
    If ( $Success -ne "200") {
        #Unable to Login
        Write-verbose $uxcommand1output.trim()
        throw "$uxhostname - Login unsuccessful, logon credentials are incorrect OR you may not be using REST Credentials.`
		For further information check `"http://www.allthingsuc.co.uk/accessing-sonus-ux-with-rest-apis`""
    }

    Write-Information "Successfully connected to $uxhostname"
    Write-verbose $uxcommand1output.trim()

    $script:DefaultSession = [PSCustomObject]@{
        host               = $uxhostname
        session            = $Session
        credentials        = $Credentials
        DefaultSessionType = $true
    }
    $DefaultSession.PSObject.TypeNames.Insert(0, "UX.SBCSessionObject")
    
    $ReturnObject = [PSCustomObject]@{
        host               = $uxhostname
        session            = $Session
        credentials        = $Credentials
        DefaultSessionType = $false            # Setting this will tell future scripts if the session has been passed to them OR if it is the default session
    }
    $ReturnObject.PSObject.TypeNames.Insert(0, "UX.SBCSessionObject")

    Return $ReturnObject
    
}


#Function to grab SBC Edge system information
Function Get-UxSystemInfo {
    <#
	.SYNOPSIS      
	 This cmdlet collects System information from Ribbon SBC.
    
    .EXAMPLE
    get-uxSystemInfo

    Gets System information from the last connected SBC. 

	.EXAMPLE
    $Creds = Get-credential
    
	PS:>$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
    
    PS:>get-uxSystemInfo -uxSession $obj

    This example stores the credential in a credential object and uses that credential to store a uxSession Object.
    With this object we can now call the get-uxSystemInfo for any session object. Therby allowing us to get information from
    any amount of SBC's.
	
	#>
	
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession
        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    $ResourceSplat = @{
        resource      = "system"
        ReturnElement = "system"
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    get-uxresource @ResourceSplat
    
}

#Function to grab UX Global Call counters
Function Get-UxSystemCallStats {
    <#
	.SYNOPSIS      
	 This cmdlet reports Call statistics from Ribbon SBC.
	 
	.DESCRIPTION
	 This cmdlet report Call statistics (global level only) from Ribbon SBC eg: Calls failed, Calls Succeeded, Call Currently Up, etc.
	
	.EXAMPLE
	get-uxsystemcallstats
    
    .EXAMPLE
    $Creds = Get-credential
    
    PS:>$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
    
    PS:>get-UxSystemCallStats -uxSession $obj

    This example stores the credential in a credential object and uses that credential to store a uxSession Object.
    With this object we can now call the get-UxSystemCallStats for any session object. Therby allowing us to get call stats from
    any amount of SBC's.

	#>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession
        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    $ResourceSplat = @{
        resource      = "systemcallstats"
        ReturnElement = "systemcallstats"
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    get-uxresource @ResourceSplat
    
}

Function Get-UxSystemLog {
    <#
	.SYNOPSIS      
	 This cmdlet reports the call logging level for a specified SBC.
	 
	.DESCRIPTION
	 This cmdlet report Call statistics (global level only) from Ribbon SBC eg: Calls failed, Calls Succeeded, Call Currently Up, etc.
	
	.EXAMPLE
	get-UxSystemLog
    
    .EXAMPLE
    $Creds = Get-credential

	PS:> $Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
    
    PS:> get-UxSystemLog -uxSession $Obj

	#>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession
        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    $ResourceSplat = @{
        resource      = "systemlog"
        ReturnElement = "systemlog"
        detail        = $true
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    get-uxresource @ResourceSplat
    
}

#Function to backup UX. When the backup succeeds there is no acknowledgement from UX.Best way to verify backup was successful is to check the backup file size
Function Invoke-UxBackup {
    <#
	.SYNOPSIS      
	 This cmdlet performs backup of Ribbon SBC
	 
	.DESCRIPTION
	This cmdlet performs backup of Ribbon SBC.
	Ensure to check the size of the backup file to verify the backup was successful as Ribbon does not acknowledge this.If a backup file is 1KB it means the backup was unsuccessful.
	
	.PARAMETER backupdestination
	Enter here the backup folder where the backup file will be copied. Ensure you have got write permissions on this folder.
	
	.PARAMETER backupfilename
	Enter here the Backup file name. The backup file will automatically be appended with .tar.gz extension.
	
	.EXAMPLE
	invoke-uxbackup -backupfilename c:\backup\lyncgw01backup01.tar.gz
	
	#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject]$uxSession,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( { $Path = Split-path $_; if (!($Path | Test-path)) { Throw "Folder Must Exist" } return $true })]
        [string]$backupfilename
    )
	
    if ($uxSession) {
        $uxSessionObj = $uxSession
        $uxHost = $uxSession.host
        $SessionVar = $uxSession.Session
    }
    else {
        $uxSessionObj = $DefaultSession
        $uxHost = $DefaultSession.host
        $SessionVar = $DefaultSession.session
    }

    # This script can be updated to use the latest Send-Command cmdlet. TODO.

    #Refeshing the token, if needed
    $ResponseCode = $((get-uxsysteminfo -uxSession $uxSessionObj).status.http_code)
    Write-verbose "Response code from Gateway $ResponseCode"	

    if ($ResponseCode -ne "200") {
        Throw "Session Expired or problem connecting to Box - Rerun Connect-uxGateway"
    }

    $args1 = ""
    $url = "https://$uxHost/rest/system?action=backup"
    if ($backupfilename -notmatch "(\.tar.gz)") {
        $backupfilename = $backupfilename -replace "\..+"
        Write-warning "The output file must be of a type tar.gz - replacing filename to $backupfilename.tar.gz"
        $FileLocation = "{0}.tar.gz" -f $backupfilename
		
    }
    else {
        $FileLocation = $backupfilename
    }
    
	
    # Lets Get the backup File and output it.
    Try {
        Invoke-RestMethod -Uri $url -Method POST -Body $args1 -WebSession $sessionvar -OutFile $FileLocation -ErrorAction Stop
    }
    Catch {
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
    }
}

#Function to return any resource (using GET)
Function Get-UxResource {
    <#
	.SYNOPSIS      
	 This cmdlet makes a GET request to any valid UX resource. For full list of valid resources refer to https://support.sonus.net/display/UXAPIDOC
	 
	.DESCRIPTION      
	 This cmdlet makes a GET request to any valid UX resource. For full list of valid resources refer to https://support.sonus.net/display/UXAPIDOC.
	 The cmdlet is one of the most powerful as you can query pretty much any UX resource which supports GET requests!
	 
	.PARAMETER resource
	Enter a valid resource name here. For valid resource names refer to https://support.sonus.net/display/UXAPIDOC

	.EXAMPLE
	This example queries a "timing" resource 
	
	get-uxresource -resource timing

	.EXAMPLE
	This example queries a "certificate" resource 
	
	get-uxresource -resource certificate

	After you know the certificate id URL using the above cmdlet, you can perform second query to find more details:

	get-uxresource -resource certificate/1
	
	.LINK
	To find all the resources which can be queried, please refer to https://support.sonus.net/display/UXAPIDOC
	
	#>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession = $DefaultSession,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$resource,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$ReturnElement,
        [Parameter(Mandatory = $false, Position = 3)]
        [string]$Arguments,
        [Parameter(Mandatory = $false, Position = 4)]
        [switch]$Details,
        [Parameter(Mandatory = $false, Position = 5)]
        [pscredential]$Credentials

    )
    <#
    #Region Getting Session
    if ($uxSession) {
        $uxSessionObj = $uxSession
        $uxHost = $uxSession.host
        $SessionVar = $uxSession.Session
    }
    else {
        if ($DefaultSession) {
            $uxSessionObj = $DefaultSession
            $uxHost = $DefaultSession.host
            $SessionVar = $DefaultSession.session
        }
        Else {
            Throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity)."
        }
    }
    #endregion

    #Region Refeshing the token, if needed
    #$ResponseCode = $((get-uxsysteminfo -uxSession $uxSessionObj).status.http_code)
    #Write-verbose "Response code from Gateway $ResponseCode"	
    #
    #if ($ResponseCode -ne "200") {
    #   Throw "Session Expired or problem connecting to Box - Rerun Connect-uxGateway"
    #}
    #endregion
    #>

    
    $url = "https://$($uxSession.host)/rest/$resource"
    if ($Details) {
        $url += "?details=true" 
    }
	
    Write-verbose "Connecting to $url"
	
    Try {
        $uxrawdata = Invoke-RestMethod -Uri $url -Method GET -WebSession $($uxSession.Session)
    }
	
    Catch {
        Try {
            if ($uxSession.DefaultSessionType) {
                Write-Warning "Session Expired - Trying to renew session to $($uxSession.host)"
                Connect-UxGateway -uxhostname $DefaultSession.host -Credentials $DefaultSession.Credentials
                $uxrawdata = Invoke-RestMethod -Uri $url -Method GET -WebSession $($uxSession.Session) -ErrorAction Stop
            }
        }
        catch {
            #Write-Verbose $uxrawdata   
            if ($_.Exception -like "*(404) Not Found*") {
                Throw "404 Returned - Unable to find Resource Are you requesting a valid resource?" 
            }
            else {
                throw "$_"
            }
        }    
    }

    $Result = ([xml]$uxrawdata.trim()).root
    $Success = $Result.status.http_code

    #Check if connection was successful.HTTP code 401 is returned which means the session has expired
    If ( $Success -eq "401") {
        # Lets Try again if it is the default session
        Try {
            if ($uxSession.DefaultSessionType) {
                Write-Warning "Session Expired - Trying to renew session to $($uxSession.host)"
                Connect-UxGateway -uxhostname $DefaultSession.host -Credentials $DefaultSession.Credentials
                $uxrawdata = Invoke-RestMethod -Uri $url -Method GET -WebSession $($DefaultSession.Session) -ErrorAction Stop
            }
            

        }
        catch {
            #Unable to Login again
            throw "We tried to reauthenticate and run your command again but failed, Try to rerun your command, OR use Connect-UxGateWay cmdlet again"
        }
        $Result = ([xml]$uxrawdata.trim()).root
        $Success = $Result.status.http_code    
    }
		
    #Check if connection was successful.HTTP code 200 is returned
    If ( $Success -ne "200") {
        #Unable to Login
        throw "Error Code $Success : Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
    }
    
    # Return data and raw data in the verbose stream if needed.
    Write-Verbose $uxrawdata
    if ($ReturnElement) {
        Return $Result.$ReturnElement    
    }
    Return $Result
   
}	

#Function to create a new resource on UX
Function New-UxResource {
    <#
	.SYNOPSIS      
	 This cmdlet initiates a PUT request to create a new UX resource. For full list of valid resources refer to https://support.sonus.net/display/UXAPIDOC
	 
	.DESCRIPTION      
	 This cmdlet  initiates a a PUT request to create a new UX resource. For full list of valid resources refer to https://support.sonus.net/display/UXAPIDOC.
	 Using this cmdlet you can create any resource on UX which supports PUT request!
	 
	.PARAMETER resource
	Enter a valid resource name here. For valid resource names refer to https://support.sonus.net/display/UXAPIDOC

	.EXAMPLE
	This example creates a new "sipservertable" resource 
	
	Grab the SIP Server table resource and next free available id
	Get-UxResource -resource sipservertable | Select -ExpandProperty sipservertable_list | Select -ExpandProperty sipservertable_pk
	
	Create new SIP server table and specify a free resource ID (15 here)
    New-UxResource -Arguments "Description=SkypeMedServers" -resource sipservertable -index 15
    
    OR 

    New-UxResource -Arguments "Description=SkypeMedServers" -resource sipservertable/15
	
	.LINK
	To find all the resources which can be queried, please refer to https://support.sonus.net/display/UXAPIDOC
	
	#>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        # The Session Object used if wanting to connect to multiple servers
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession = $DefaultSession,

        # The Resource you wish to hit, such as sipservertable
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$resource,

        # Used with other cmdlets to help tidy up the XML return so the tree is not too deep.
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$ReturnElement,

        # Pass any argument that you wish to be built, such as Description=Skype
        [Alias("Args", "Options", "Settings")]
        [Parameter(Mandatory = $false, Position = 3)]
        [string]$Arguments,

        # If using a tidier method or planning on looping, you could use the Index Tag which will add to the end of the resource name /1
        [Parameter(Mandatory = $true, Position = 4)]
        [Int]$Index,

        # Currently not used, Will be used infuture for automatic refesh tokens.
        [Parameter(Mandatory = $false, Position = 5)]
        [pscredential]$Credentials

    )
    
    

    #Region Refeshing the token, if needed
    #$ResponseCode = $((get-uxsysteminfo -uxSession $uxSessionObj).status.http_code)
    #Write-verbose "Response code from Gateway $ResponseCode"	
    #
    #if ($ResponseCode -ne "200") {
    #   Throw "Session Expired or problem connecting to Box - Rerun Connect-uxGateway"
    #}
    #endregion


 
    $url = "https://$($uxSession.host)/rest/$resource/$Index"
    Write-verbose "Connecting to $url"
    Write-verbose "Adding: $Arguments "
    
    # Lets check the User Actually wants to make this change
    $msg = "Adding A New Entry to $resource on the $($uxSession.host) Gateway with ID $Index"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        Try {
            $uxrawdata = Invoke-RestMethod -Uri $url -Method PUT -Body $Arguments -WebSession $($uxSession.Session) -ErrorAction Stop
        }
	
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
    
        $Result = ([xml]$uxrawdata.trim()).root
        $Success = $Result.status.http_code
        
        
        switch ( $Success) {            
            "200" { Write-Verbose "Happy with the response" }
            "401" { throw "Error creating the new entry, is there an existing record at $url? .The error message is $_" } 
            "500" { Write-Verbose -Message $uxrawdata; throw "Unable to create a new resource. Ensure you have entered a unique resource id.Verify this using `"get-uxresource`" cmdlet" }   
            default { throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_" }
        }

	
        # Return data and raw data in the verbose stream if needed.
        Write-Verbose $uxrawdata
        if ($ReturnElement) {
            Return $Result.$ReturnElement    
        }
        Return $Result
    }
}	


Function Send-UxCommand {
    <#
	.SYNOPSIS      
	 This cmdlet initates a POST request to send commands to the UX resource. For full list of valid resources refer to https://support.sonus.net/display/UXAPIDOC/Resource+-+system
	 
	.DESCRIPTION      
	 This cmdlet initates a POST request to modify existing UX resource. For full list of valid resources refer to https://support.sonus.net/display/UXAPIDOC/Resource+-+system
	 
	.PARAMETER resource
	Enter a valid resource name here. For valid resource names refer to https://support.sonus.net/display/UXAPIDOC

    .EXAMPLE
    Send-UxCommand -command reboot

.EXAMPLE
    Send-UxCommand -command reboot -uxSession $1stGateway

	.LINK
	To find all the resources which can be queried, please refer to https://support.sonus.net/display/UXAPIDOC
	
	#>
    
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession = $DefaultSession,

        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Command,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]$Arguments,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateScript( { $Path = Split-path $_; if (!($Path | Test-path)) { Throw "Folder Must Exist" } return $true })]
        [string]$OutPutFilename,

        [Parameter(Mandatory = $false, Position = 4)]
        [string]$ReturnElement,

        [Parameter(Mandatory = $false, Position = 5)]
        [pscredential]$Credentials

    )
    


    #Region Refeshing the token, if needed
    #$ResponseCode = $((get-uxsysteminfo -uxSession $uxSessionObj).status.http_code)
    #Write-verbose "Response code from Gateway $ResponseCode"	
    #
    #if ($ResponseCode -ne "200") {
    #   Throw "Session Expired or problem connecting to Box - Rerun Connect-uxGateway"
    #}
    #endregion

    # The Command MUST be in lowercase so converting
    $url = "https://$($uxSession.host)/rest/system?action=$($command.ToLower())"
    Write-verbose "Connecting to $url"
    Write-verbose "Adding: $Arguments"
    
    # Lets check the User Actually wants to make this change
    $msg = "Running $Command on the $($uxSession.host) Gateway"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        Try {
            $options = @{
                uri         = $url
                Method      = "POST"
                Body        = $Arguments
                WebSession  = $uxSession.Session
                ErrorAction = "Stop"
            }
            if ($OutPutFilename) { $options.OutFile = $OutPutFilename }

            $uxrawdata = Invoke-RestMethod @options
        }
	
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
    
        $Result = ([xml]$uxrawdata.trim()).root
        $Success = $Result.status.http_code
        
        switch ( $Success) {            
            "200" { Write-Verbose "Happy with the response" }
            "401" { throw "Error creating the new entry, is there an existing record at $url? .The error message is $_" } 
            "500" { Write-Verbose -Message $uxrawdata; throw "Unable to create a new resource. Ensure you have entered a unique resource id.Verify this using `"get-uxresource`" cmdlet" }   
            default { throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_" }
        }   
       
	
        # Return data and raw data in the verbose stream if needed.
        Write-Verbose $uxrawdata
        if ($ReturnElement) {
            Return $Result.$ReturnElement    
        }
        Return $Result
    }
}

#Function to delete a resource on UX. 200OK is returned when a resource is deleted successfully. 500 if resource did not exist or couldn't delete it
Function Remove-UxResource {
    <#
	.SYNOPSIS      
	 This cmdlet initates a DELETE request to remove a UX resource. For full list of valid resources refer to https://support.sonus.net/display/UXAPIDOC
	 
	.DESCRIPTION      
	 Whilst primarily used by the internal functions, you can use this function with your own scripts. 
     As this is likely to overwrite some of your SBC settings the ConfirmPreferences have been set to HIGH!
     If you would like to prevent the confirm prompt use -confirm:$false when calling this function.
     This can be dangerous if you are looping consider yourself WARNED. :-)

	 You can delete any resource which supports DELETE request.
	 
	.PARAMETER resource
	Enter a valid resource name here. For valid resource names refer to https://support.sonus.net/display/UXAPIDOC

	.EXAMPLE
	Extract the transformation table id of the table you want to delete
	get-uxtransformationtable
	
	Now execute remove-uxresource cmdlet to delete the transformation table
	remove-uxresource -resource transformationtable/13
    
    .EXAMPLE
	Same as Above but if you are scripting it use -confirm:$false
	get-uxtransformationtable
	
	Now execute remove-uxresource cmdlet to delete the transformation table
	remove-uxresource -resource transformationtable/13 -confirm:$false

	.EXAMPLE
	 Extract the SIP Server table resource and find the id of the table you want to delete
	((get-uxresource -resource sipservertable).sipservertable_list).sipservertable_pk
	
	Now execute remove-uxresource cmdlet
	remove-uxresource -resource sipservertable/10
	
	.LINK
	To find all the resources which can be queried, please refer to https://support.sonus.net/display/UXAPIDOC
	
	#>

    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession = $DefaultSession,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$resource,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]$ReturnElement,

        [Parameter(Mandatory = $false, Position = 3)]
        [string]$Arguments,

        [Parameter(Mandatory = $false, Position = 4)]
        [Int]$Index,

        [Parameter(Mandatory = $false, Position = 5)]
        [pscredential]$Credentials

    )

      
    if ($resource -contains "http://") {
        Throw "Resource is not properly formatted. Please only pass the resource you wish to remove not the whole address such as transformationtable then index of the entry"
    }

    #The URL  which will be passed to the UX
    $url = "https://$($uxSession.host)/rest/$resource"
    if ($index) { $url += "/$index" }
    Write-verbose "Removing $url"
    Write-verbose "With: $Arguments "
    

    $msg = "Deleting A New Entry to $resource on the $($uxSession.host) Gateway"
    if ($index) { $msg += "with ID $Index" }
    if ($PSCmdlet.ShouldProcess($($msg))) {
        Try {
            $uxrawdata = Invoke-RestMethod -Uri $url -Method DELETE -Body $Arguments -WebSession $uxSession.Session -ErrorAction Stop
        }
	
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
    
        $Result = ([xml]$uxrawdata.trim()).root
        $Success = $Result.status.http_code
		
        
        switch ( $Success) {            
            "200" { Write-Verbose "Happy with the response" }
            "401" { throw "Error creating the new entry, is there an existing record at $url? .The error message is $_" } 
            "500" { Write-Verbose -Message $uxrawdata; throw "Unable to create a new resource. Ensure you have entered a unique resource id.Verify this using `"get-uxresource`" cmdlet" }   
            default { throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_" }
        }

	
        # Return data and raw data in the verbose stream if needed.
        Write-Verbose $uxrawdata
        if ($ReturnElement) {
            Return $Result.$ReturnElement    
        }
        Return $Result
    }
}		

#Function to create a modify and existing resource on the UX
Function Set-UxResource {
    <#
	.SYNOPSIS      
	 This cmdlet initates a POST request to modify existing UX resource. For full list of valid resources refer to https://support.sonus.net/display/UXAPIDOC
	 
	.DESCRIPTION      
     Whilst primarily used by the internal functions, you can use this function with your own scripts. 
     As this is likely to overwrite some of your SBC settings the ConfirmPreferences have been set to HIGH!
     If you would like to prevent the confirm prompt use -confirm:$false when calling this function.
     This can be dangerous if you are looping consider yourself WARNED. :-)
	 
	.PARAMETER resource
	Enter a valid resource name here. For valid resource names refer to https://support.sonus.net/display/UXAPIDOC

	.EXAMPLE
	Assume you want to change the description of one of the SIPServer table.
	Using Get find the ID of the sip server table
	((get-uxresource -resource sipservertable).sipservertable_list).sipservertable_pk
	
	Once you have found the ID, issue the cmdlet below to modify the description
	set-uxresource -args Description=SBA2 -resource sipservertable/20
	
	.EXAMPLE
	Assume you want to change Description of the transformation table.
	Extract the transformation table id of the table you want to modify
	get-uxtransformationtable
	
	Once you have found the ID, issue the cmdlet below to modify the description
	set-uxresource -args "Description=Test5" -resource "transformationtable/12"
	
	.LINK
	To find all the resources which can be queried, please refer to https://support.sonus.net/display/UXAPIDOC
	
	#>

    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        [Parameter(Mandatory = $false, Position = 5)]
        [PSCustomObject]$uxSession = $DefaultSession,

        [Parameter(Mandatory = $true, Position = 0)]
        [string]$resource,

        [Parameter(Mandatory = $false, Position = 3)]
        [string]$ReturnElement,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]$Arguments,

        [Parameter(Mandatory = $true, Position = 1)]
        [Int]$Index,

        [Parameter(Mandatory = $false, Position = 6)]
        [pscredential]$Credentials

    )

 	
    #The URL  which will be passed to the UX
    $url = "https://$($uxSession.host)/rest/$resource/$index"
    Write-verbose "Editing $url"
    Write-verbose "With: $Arguments "
    

    $msg = "Deleting A New Entry to $resource on the $($uxSession.host) Gateway with ID $Index"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        Try {
            $uxrawdata = Invoke-RestMethod -Uri $url -Method POST -Body $Arguments -WebSession $uxSession.Session -ErrorAction Stop
        }
	
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	    
        $Result = ([xml]$uxrawdata.trim()).root
        $Success = $Result.status.http_code
	    
        switch ( $Success) {            
            "200" { Write-Verbose "Happy with the response" }
            "401" { throw "Error creating the new entry, is there an existing record at $url? .The error message is $_" } 
            "500" { Write-Verbose -Message $uxrawdata; throw "Unable to create a new resource. Ensure you have entered a unique resource id.Verify this using `"get-uxresource`" cmdlet" }   
            default { throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_" }
        }
	
        # Return data and raw data in the verbose stream if needed.
        Write-Verbose $uxrawdata
        if ($ReturnElement) {
            Return $Result.$ReturnElement    
        }
        Return $Result
    }
}	


Function Get-UxTransformationTable {

    <#
	.SYNOPSIS      
	 This cmdlet reports The Transformation from Ribbon SBC.
	 
	.DESCRIPTION
	 TBC
	
	.EXAMPLE
	get-uxtransformationtable
    
    .EXAMPLE
    $Creds = Get-credential
	$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
	get-uxtransformationtable -uxSession $Obj

	#>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #To find the ID of the transformation table execute "get-uxtransformationtable" cmdlet'
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$uxTransformationTableId
        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    $ResourceSplat = @{
        resource      = "transformationtable"
        ReturnElement = "transformationtable_list"
        Details       = $true
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }
    $TopLevel = (get-uxresource @ResourceSplat).transformationtable


    if ($uxTransformationTableId) {
        # We Need to pull the top Level First



        $ResourceSplat = @{
            resource      = "transformationtable/$uxtransformationtableid/transformationentry"
            ReturnElement = "transformationentry_list"
            Details       = $true
        }
        if ($uxSession) { $ResourceSplat.uxSession = $uxSession }
        $SubLevel = (get-uxresource @ResourceSplat).transformationentry

        #Lets Get The Sequence
        $Seq = $TopLevel | Where-Object { $_.id -eq $uxTransformationTableId } | Select-Object -ExpandProperty Sequence
        
        $OrderedList = Get-UxOrderedList -Sequence $Seq -List $SubLevel
      

        # Lets Build a Temp object where we can store the top level then the entires.
        #$TempReturn = [PSCustomObject]@{
        #    Table   = $TopLevel.transformationtable | Where-Object { $_.id -eq $uxTransformationTableId }
        #    Entries = $OrderedList
        #}
        
        
        # Lets Finally Build the Return Object 
        return $OrderedList
    }
    else {
        return $TopLevel
    }
        
    
}

Function Copy-UxTransformationTables {
    <#
	.SYNOPSIS      
	 This Cmdlet will take a list of transformation tables from one SBC and Copy them to another
	 
	.DESCRIPTION
     Copying data from one SBC to another is tedious work, this cmdlet will take a list of transformation tables and will build them
     on the destination SBC. To ensure we prevent unitntended results the rules will be disabled unless the -enabled switch is used.

     The cmdlet will enumerate through the entries unless you use the -confirm:$false parameter

     Unless specified all entries will be marked as disabled when moved to other SBC. We will also update the description on the destination
     SBC with a small tag which shows what the order they were in on the source AND the enabled status at time of copying.

    .EXAMPLE
    $SourceCreds = Get-Credential
    
    PS:> $DestinationCreds = Get-Credential
    
    PS:> $SourceGateWay = Connect-uxGateway -uxhostname 192.168.1.51 -credentials $SourceCreds
    
    PS:> $DestinationGateway = Connect-uxGateway -uxhostname 192.168.1.52 -credentials $DestinationCreds
    
    PS:> Copy-UxTransformationTables -SourceSession $SourceGateWay -DestinationSession $DestinationGateway
    

    This example is a basic copy all entries.
    
    
    #>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        # This is the source session where you want to copy the rules from
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject]$SourceSession,
        # This is the destination session See help how to create a session variable
        [Parameter(Mandatory = $true, Position = 1)]
        [PSCustomObject]$DestinationSession,
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 2)]
        [int]$TableID,
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$Enabled
    )

    Write-Verbose "Source SBC $($SourceSession.host)"
    Write-Verbose "Destination SBC $($DestinationSession.host)"
    Write-verbose "Checking Both Sessions"
    try {
        $null = Get-UxSystemInfo -uxSession $SourceSession -Verbose:$false
    }
    catch {
        Throw "$($SourceSession.host) Session has problems, please ensure both sessions have been accessed in the last 10 mins."
    }
    try {
        $null = Get-UxSystemInfo -uxSession $DestinationSession -Verbose:$false
    }
    catch {
        Throw "$($DestinationSession.host) Session has problems, please ensure both sessions have been accessed in the last 10 mins."
    }
    Write-verbose "Both Sessions Appear to be ok, continuing"
    if ($TableID) {
        $SourceTransformationTable = Get-UxTransformationTable -uxSession $SourceSession -Verbose:$false | Where-object { $_.id -eq $TableID }
        Write-Verbose "Getting $($SourceTransformationTable.description) Only"
    }
    Else { 
        $SourceTransformationTable = Get-UxTransformationTable -uxSession $SourceSession -Verbose:$false
    }
    foreach ($Entry in $SourceTransformationTable) {
        $EntryObject = ($Entry | New-UxURLandPSObject).posh
        $EntryObject.Description += " - Copy from $($SourceSession.host)"
        
        # Lets get the Transformation Rules
        $TransformationRules = Get-UxTransformationTable $EntryObject.id -Verbose:$false
        
        
        
        
        
        
        Write-verbose "Removing Uncopyable attributes"
        $EntryObject.psobject.properties.remove('href')
        $EntryObject.psobject.properties.remove('id')
        $EntryObject.psobject.properties.remove('sequence')
        Write-verbose "Copying Item:"
        Write-Verbose $EntryObject
        $HTMLFormated = ($EntryObject | New-UxURLandPSObject).HtmlStr
        Write-Verbose $HTMLFormated




        # Lets Get the next id on the Destination box
        [int]$NewTransformationTableId = (get-uxtransformationtable -uxSession $DestinationSession -verbos:$false | select-object -ExpandProperty id | Measure-Object -Maximum).Maximum + 1 

        # Lets Get Ready to add
        $ResourceSplat = @{
            resource      = "transformationtable"
            index         = $NewTransformationTableId
            ReturnElement = "transformationtable"
            Arguments     = $HTMLFormated
            uxSession     = $DestinationSession
            Verbose       = $false
        }
        
        

        Write-Verbose "Submitting Data"
        
        Write-Verbose "Adding $($EntryObject.Description) to Transformation Table on the $($DestinationSession.host) Gateway with ID $NewTransformationTableId"
        $msg = "Adding $($EntryObject.Description) to Transformation Table on the $($DestinationSession.host) Gateway with ID $NewTransformationTableId"
        if ($PSCmdlet.ShouldProcess($($msg))) {
            Write-verbose "Returning the updated table"
            $NewTableResult = new-uxresource @ResourceSplat -WhatIf:$PSBoundParameters.ContainsKey('WhatIf')
            Write-Verbose "Returned Table id $($NewTableResult.id)"

            # Time to add the entries
            $TransformationRules | ForEach-Object { 
                # Again we do this as it is easier to manipulate a PSobject rather than an XmlElement
                $PoshObject = ($_ | New-UxURLandPSObject).posh
            
            
                # As back up to ordering, and to help SBC engineers we add (# Number to the description)
                $PoshObject.description = "(#{0}-En{1}) {2}" -f $PoshObject.ListOrder, $PoshObject.ConfigIEState, $PoshObject.description

                # Now we see if the enabled switch has been applied, if not we then tell the rule to be disabled.
                if (-not $Enabled) {
                    $PoshObject.ConfigIEState = 0
                }
                
                

                #Now we remove stuff that cannot apply on a different box
                $PoshObject.psobject.properties.remove('href')
                $PoshObject.psobject.properties.remove('id')
                $PoshObject.psobject.properties.remove('ListOrder')

                $HTMLFormated = ($PoshObject | New-UxURLandPSObject).HtmlStr
            
                # Lets Get the next Entr ID
                [int]$NewTransformationEntryId = (get-uxtransformationentry -uxTransformationTableId $NewTableResult.id -uxSession $DestinationSession -verbose:$false | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | Measure-Object -Maximum).Maximum + 1 

                Write-Verbose "Gonna Add this"
                Write-Verbose $HTMLFormated
                Write-Verbose "To the New SBC in table $($NewTableResult.id)"

                $EntrySplat = @{
                    resource      = "transformationtable/$($NewTableResult.id)/transformationentry"
                    index         = $NewTransformationEntryId
                    ReturnElement = "transformationtable"
                    uxSession     = $DestinationSession
                    Arguments     = $HTMLFormated
                    verbose       = $false
                    confirm       = $false
                }
                try {
                    $EntryReturn = new-uxresource @EntrySplat -WhatIf:$PSBoundParameters.ContainsKey('WhatIf') 
                }
                catch {
                    Write-Error "Failed to Add : $HTMLFormated"  
                } 
                Write-verbose $EntryReturn
            }

        }
    }

}

<#
Function Copy-UxTransformationEntry {
    <#
	.SYNOPSIS      
	 This Cmdlet will take a list of transformation entry from one SBC and Copy them to another
	 
	.DESCRIPTION
     Copying data from one SBC to another is tedious work, this cmdlet will take a list of transformation tables and will build them
     on the destination SBC. To ensure we prevent unitntended results the rules will be disabled unless the -enabled switch is used.

     The cmdlet will enumerate through the entries unless you use the -ALL parameter

	.EXAMPLE
	Copy-UxTransformationTables -SourceSession $SourceGateWay -DestinationSession $DestinationGateway
    
    
    
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject]$SourceSession,
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $true, Position = 1)]
        [PSCustomObject]$DestinationSession,
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 2)]
        [switch]$ALL,
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$Enabled
    )
}
#>




Function Get-UxOrderedList {
    <#
	.SYNOPSIS      
	 This cmdlet orders a list based on a sequence provided.
	 
	.DESCRIPTION
     This function is mainly used internally to get a list of entries and sort the list based on their parent's sequence.
     We add a XML entry, called ListOrder to each Entry which the user can then sort upon using the following command
     $Results | Sort Listorder

	.EXAMPLE
	Get-UxOrderedList -Sequence $Seq -List $List
    
    
    #>
    
    [cmdletbinding()]
    Param(
        # This parameter needs a string in the format '1,3,2,8' The function will then split tis internally to create an array
        [Parameter(Mandatory = $true, Position = 0)]
        [String]$Sequence,
        # This parameter needs a List of entries from the SBC with an id element. Ideally in the "5:1" format.
        [Parameter(Mandatory = $true, Position = 1)]
        $List
    )

    $SeqArray = $Sequence.Split(",")
    for ($i = 0; $i -lt $SeqArray.Count; $i++) {
        #$SearchFilter = "{0}:{1}" -f $uxtransformationtableid, $SeqArray[$i]
        $CurrentEntry = $List | Where-object { $_.id -like "*:$($SeqArray[$i])" }
        $child = $CurrentEntry.OwnerDocument.CreateElement("ListOrder")
        $child.InnerText = $($i + 1)

        # This is Really funky... If you don't void the return, you will not get an output For $CurrentEntry.
        [void]$CurrentEntry.AppendChild($child)
        
    }
    return $($List | Sort-Object ListOrder)

}

Function Get-UxTransformationEntry {
    <#
	.SYNOPSIS      
	 This cmdlet reports The Transformation from Ribbon SBC.
	 
	.DESCRIPTION
     Gets all the entries but in an unordered form. As the sequence is stored at the level above 
     use get-UxTransformationTable 'TableID' to get ordered list as per sequence.
	
	.EXAMPLE
	get-uxtransformationEntry -uxTransformationTableId 4
    
    .EXAMPLE
    $Creds = Get-credential
	$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
	get-uxtransformationtable -uxSession $Obj -uxTransformationTableId 4

	#>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #To find the ID of the transformation table execute "get-uxtransformationtable" cmdlet'
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$uxTransformationTableId

        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    $ResourceSplat = @{
        resource      = "transformationtable/$uxtransformationtableid/transformationentry"
        ReturnElement = "transformationentry_list"
        Details       = $true
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }


    #Further filtering of the object for this option - Here we want to see the whole details of the object.
    $Return = get-uxresource @ResourceSplat
    Write-Output $return.transformationentry
    
}

Function New-UxTransformationTable {
    <#
	.SYNOPSIS      
	 This cmdlet creates a new transformation table (not transformation table entry)
	 
	.DESCRIPTION
	This cmdlet creates a transformation table (not transformation table entry).
	
	.PARAMETER Description
	Enter here the Description (Name) of the Transformation table.This is what will be displayed in the Ribbon GUI
	
	.EXAMPLE
	 new-uxtransformationtable -Description "LyncToPBX"
	
        #>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #Description of the new tablle
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateLength(1, 64)]
        [string]$Description
    )
        

    # First thing we need to do is get a new TableId
    try {
        if ($uxSession) {
            [int]$NewTransformationTableId = (get-uxtransformationtable -uxSession $uxSession | select-object -ExpandProperty id | Measure-Object -Maximum).Maximum + 1 
        }
        else {
            [int]$NewTransformationTableId = (get-uxtransformationtable | select-object -ExpandProperty id | Measure-Object -Maximum).Maximum + 1 
        }
    }
    catch {
        Throw "Unable to get a new table id"
    }

    #Lets create the information to upload, this nees to be in HTTP format for the PUT
    $HTTPDescription = "Description=$Description"

    $ResourceSplat = @{
        resource      = "transformationtable"
        index         = $NewTransformationTableId
        ReturnElement = "transformationtable"
        Arguments     = $HTTPDescription
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    Write-Verbose "Submitting Data"
    Write-verbose "Returning the updated table"
    $msg = "Adding A New Entry to Transformation Table on the Gateway with ID $NewTransformationTableId"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        $Return = new-uxresource @ResourceSplat -WhatIf:$PSBoundParameters.ContainsKey('WhatIf') -Confirm:$false      
    }
    Write-Output $return

}

#Function to create new transformation table entry
Function New-UxTransformationEntry {
    <#
	.SYNOPSIS      
	 This cmdlet creates transformation entries in existing transformation table
	 
	.DESCRIPTION
	This cmdlet creates transformation entries in existing transformation table.You need to specify the transformation table where these transformation entries should be created.
	
	.PARAMETER TransformationTableId
	Enter here the TransformationTableID of the transformation table where you want to add the transformation entry. This can be extracted using "get-uxtransformationtable" cmdlet
	
	.PARAMETER InputFieldType
	Enter here the code (integer) of the Field you want to add, eg:If you want to add "CalledNumber" add 0. Full information on which codes maps to which field please refer http://bit.ly/SBC-TransfomationCodes

	.PARAMETER InputFieldValue
	Enter the value which should be matched.eg: If you want to match all the numbers between 2400 - 2659 you would enter here "^(2([45]\d{2}|6[0-5]\d))$"

	.PARAMETER OutputFieldType
	Enter here the code (integer) of the Field you want to add, eg:If you want to add "CalledNumber" add 0. Full information on which codes maps to which field please refer http://bit.ly/SBC-TransfomationCodes

	.PARAMETER OutputFieldValue
	Enter here the output of the Input value.eg: If you want to change input of "^(2([45]\d{2}|6[0-5]\d))$" to +44123456XXXX, you would enter here +44123456\1

	.PARAMETER Description
	Enter here the Description (Name) of the Transformation entry. This is what will be displayed in the Ribbon GUI

	.PARAMETER MatchType
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.EXAMPLE
	Assume you want to create a new transformation table.
	First determine the ID of the transformation table in which you want to create the new transformation entry.
	
	get-uxtransformationtable

	This example creates an Optional (default) transformation entry converting Called Number range  2400 - 2659  to Called Number +44123456XXXX
	
	new-uxtransformationentry -TransformationTableId 6 -InputFieldType 0 -InputFieldValue '^(2([45]\d{2}|6[0-5]\d))$' -OutputFieldType 0 -OutputFieldValue '+44123456\1' -Description "ExtToDDI"
	
	.EXAMPLE
	This example creates an Optional transformation entry converting Calling Number beginning with 0044xxxxxx to Calling Number +44xxxxxx
	
	new-uxtransformationentry -TransformationTableId 3 -InputFieldType 3 -InputFieldValue '00(44\d(.*))' -OutputFieldType 3 -OutputFieldValue '+\1' -Description "UKCLIToE164"
	
	.EXAMPLE
	This example creates a Mandatory CLI (Calling Number)passthrough
	
	new-uxtransformationentry -TransformationTableId 9 -InputFieldType 3 -InputFieldValue '(.*)' -OutputFieldType 3 -OutputFieldValue '\1' -Description "PassthroughCLI" -MatchType 0
	
	.LINK
	For Input/Output Field Value Code mappings, please refer to http://bit.ly/SBC-TransfomationCodes
	
	#>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession,

        [Parameter(Mandatory = $true, Position = 1)]
        [int]$TransformationTableId,
		
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Refer http://bit.ly/SBC-TransfomationCodes for further detail")]
        [ValidateRange(0, 38)]
        [int]$InputFieldType,
		
        [Parameter(Mandatory = $true, Position = 3)]
        [ValidateLength(1, 256)]
        [string]$InputFieldValue,
		
        [Parameter(Mandatory = $true, Position = 4, HelpMessage = "Refer http://bit.ly/SBC-TransfomationCodes for for further detail")]
        [ValidateRange(0, 38)]
        [string]$OutputFieldType,
		
        [Parameter(Mandatory = $true, Position = 5)]
        [ValidateLength(1, 256)]
        [string]$OutputFieldValue,
		
        [Parameter(Mandatory = $true, Position = 6)]
        [ValidateLength(1, 64)]
        [string]$Description,
		
        [Parameter(Mandatory = $False, Position = 7)]
        [ValidateSet(0, 1)]
        [int]$MatchType = 1
		
    )
    # First thing we need to do is get a new TableId for the entry
    #DEPENDENCY ON get-uxtransformationentry FUNCTION TO GET THE NEXT AVAILABLE TRANSFORMATIONTABLEID
    try {
        if ($uxSession) {
            [int]$NewTransformationEntryId = (get-uxtransformationentry -uxTransformationTableId $TransformationTableId -uxSession $uxSession | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | Measure-Object -Maximum).Maximum + 1 
        }
        else {
            [int]$NewTransformationEntryId = (get-uxtransformationentry -uxTransformationTableId $TransformationTableId | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | Measure-Object -Maximum).Maximum + 1 
        }
    }
    catch {
        Throw "Command failed when trying to execute the Transformationtableentryid using `"get-uxtransformationentry`" cmdlet.The error is $_"
    }

  
    #Replace "+" with "%2B" as + is considered a Space in HTTP/S world, so gets processed as space when used in a command
    $InputFieldValue = $InputFieldValue.replace("+", '%2B')
    $OutputFieldValue = $OutputFieldValue.replace("+", '%2B')
  
    #Variable which contains all the information we require to create a transformation table.
    $args2 = "Description=$Description"
    $args2 += "&InputField=$InputFieldType"
    $args2 += "&InputFieldValue=$InputFieldValue"
    $args2 += "&OutputField=$OutputFieldType"
    $args2 += "&OutputFieldValue=$OutputFieldValue"
    $args2 += "&MatchType=$MatchType"
	
  

    $ResourceSplat = @{
        resource      = "transformationtable/$TransformationTableId/transformationentry"
        index         = $NewTransformationEntryId
        ReturnElement = "transformationtable"
        Arguments     = $args2
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    Write-Verbose "Submitting Data"
    Write-verbose "Returning the updated table"
    $msg = "Adding A New Entry to transformationtable/$TransformationTableId/transformationentry Table on the Gateway with ID $NewTransformationTableId"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        $Return = new-uxresource @ResourceSplat -WhatIf:$PSBoundParameters.ContainsKey('WhatIf') -Confirm:$false      
    }
    Write-Output $return
	
}

#Function to get sipserver table
Function Get-UxSipServerTable {
    <#
	.SYNOPSIS      
	 This cmdlet displays all the sipserver table names and ID's
	
	.EXAMPLE
	 get-uxsipservertable
       
    .EXAMPLE
	 get-uxsipservertable 3

    .EXAMPLE
    $Creds = Get-credential
	$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
	get-uxsipservertable -uxSession $Obj

	#>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,

        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSipServerTableId
        
        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    if ($uxSipServerTableId) {
        $ResourceSplat = @{
            resource      = "sipservertable/$uxSipServerTableId/sipserver"
            ReturnElement = "sipserver_list"
            Details       = $true
        }
    }
    else {
        $ResourceSplat = @{
            resource      = "sipservertable"
            ReturnElement = "sipservertable_list"
            detail        = $true
        }
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    #Further filtering of the object for this option - Here we want to see the whole details of the object.
    $Return = get-uxresource @ResourceSplat
    if ($uxSipServerTableId) {
        Write-Output $return.sipserver
    }
    else {
        Write-Output $return.sipservertable
    }


}

#Function to create new sipserver table
Function New-UxSipServerTable {
    <#
	.SYNOPSIS      
	 This cmdlet creates a new sipserver table (not sipserver table entry)
	 
	.DESCRIPTION
	This cmdlet creates a sipserver table (not sipserver table entry).
	
	.PARAMETER Description
	Enter here the Description (Name) of the sipserver table.This is what will be displayed in the Ribbon GUI
	
	.EXAMPLE
	 new-uxsipservertable -Description "LyncToPBX"
	
	#>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #Description of the new tablle
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateLength(1, 64)]
        [string]$Description
    )
    
    # First thing we need to do is get a new TableId
    try {
        if ($uxSession) {
            [int]$sipservertableid = (get-uxsipservertable -uxSession $uxSession | Select-Object -ExpandProperty id | Measure-Object -Maximum).Maximum + 1 
        }
        else {
            [int]$sipservertableid = (get-uxsipservertable | Select-Object -ExpandProperty id | Measure-Object -Maximum).Maximum + 1 
        }
    }
    catch {
        Throw "Unable to get a new table id"
    }

    
    #Lets create the information to upload, this nees to be in HTTP format for the PUT
    $HTTPDescription = "Description=$Description"

    $ResourceSplat = @{
        resource      = "sipservertable"
        index         = $sipservertableid
        ReturnElement = "sipservertable"
        Arguments     = $HTTPDescription
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    Write-Verbose "Submitting Data"
    Write-verbose "Returning the updated table"
    $msg = "Adding A New Entry to sipservertable Table on the Gateway with ID $sipservertableid"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        $Return = new-uxresource @ResourceSplat -WhatIf:$PSBoundParameters.ContainsKey('WhatIf') -Confirm:$false      
    }
    Write-Output $return

}

#Function to create new sipserver entry
Function New-UxSipServerEntry {
    <#
	.SYNOPSIS      
	 This cmdlet creates a new host/domain in existing sipserver table
	 
	.DESCRIPTION
	This cmdlet creates a new host in an existing sipserver table.You need to specify the sipserver table where these transformation entries should be created.
	
	.PARAMETER SipServerTableId
	Enter here the SIPServer ID of the sipserver table where you want to add a new host entry. This can be extracted using "get-uxsipservertable" cmdlet

	.PARAMETER ServerLookup
	Enter here the SIPServer ID of the sipserver table where you want to add a new host entry. This can be extracted using "get-uxsipservertable" cmdlet
	
	.PARAMETER Priority
	Enter here the code (integer) of the Field you want to add, eg:If you want to add "CalledNumber" add 0. Full information on which codes maps to which field please refer http://bit.ly/Iy7JQS

	.PARAMETER Host
	Enter the value which should be matched.eg: If you want to match all the numbers between 2400 - 2659 you would enter here "^(2([45]\d{2}|6[0-5]\d))$"

	.PARAMETER HostIpVersion
	Enter here the code (integer) of the Field you want to add, eg:If you want to add "CalledNumber" add 0. Full information on which codes maps to which field please refer http://bit.ly/Iy7JQS

	.PARAMETER Port
	Enter here the output of the Input value.eg: If you want to change input of "^(2([45]\d{2}|6[0-5]\d))$" to +44123456XXXX, you would enter here +44123456\1

	.PARAMETER Protocol
	Enter here the Description (Name) of the Transformation entry. This is what will be displayed in the Ribbon GUI

	.PARAMETER TLSProfile
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.PARAMETER KeepAliveFrequency
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.PARAMETER RecoverFrequency
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.PARAMETER LocalUserName
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.PARAMETER PeerUserName
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.PARAMETER RemoteAuthorizationTable
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.PARAMETER ContactRegistrantTable
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.PARAMETER SessionURIValidation
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.PARAMETER ReuseTransport
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.PARAMETER TransportSocket
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional

	.PARAMETER ReuseTimeout
	Enter here if the Transformation entry you will create will be Mandatory(0) or Optional(1). If this parameter is not specified the transformation table will be created as Optional


	.EXAMPLE
	
	.EXAMPLE
	
	.EXAMPLE
	
	.LINK
	
	
	#>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 28)]
        [PSCustomObject]$uxSession,

        # Table ID to add entry
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$SipServerTableId,


        # Specifies the method to use to lookup SIP servers IP/FQDN 
        [Parameter(Mandatory = $false, Position = 1)]
        [validateSet(0, 1)]
        [int]$ServerLookup = 0,

        # Specifies the method to use to lookup SIP servers eConventionalSrvr 
        [Parameter(Mandatory = $false, Position = 2)]
        [validateSet(0, 1, 2)]
        [int]$ServerType = 0,

        # Specifies the weight of the server in case it's defined in the SRV record.
        [Parameter(Mandatory = $false, Position = 3)]
        [validateRange(0, 65535)]
        [int]$Weight = 0,

        # Specifies the IP address or FQDN where this Signaling Group sends SIP messages. If an FQDN is configured all the associated servers are included and used according to the server selection configuration element.
        [Alias("ComputerName", "Server", "FQDN", "Host")]
        [Parameter(Mandatory = $true, Position = 4)]
        [validateLength(0, 256)]
        [string]$Hostname,

        # Specifies whether the FQDN should be resolved into IPv4 addresses or IPv6 addresses. If this is a SRV record, this field specifies whether the resulting FQDNs are resolved into IPv4 or IPv6 addresses. By default, the SBC Edge resolves the FQDN into IPv4 addresses.
        [Parameter(Mandatory = $false, Position = 5)]
        [validateSet(0, 1)]
        [int]$HostIpVersion = 0,

        # Specifies the Domain where this Signaling Group sends SRV queries.
        [Parameter(Mandatory = $false, Position = 6)]
        [validateLength(0, 256)]
        [string]$DomainName = "",

        # The name of the service to be placed in the SRV request.
        [Parameter(Mandatory = $false, Position = 7)]
        [validateLength(0, 64)]
        [string]$ServiceName = "sip",

        # Specifies the port number to send SIP messages.
        [Parameter(Mandatory = $false, Position = 8)]
        [validateRange(1024, 65535)]
        [int]$Port = 5060,

        # Specifies number of re-usable sockets 
        # This option is available when ReuseTransport is set to True. When ReuseTransport is false, this needs to be set to 0
        [Parameter(Mandatory = $false, Position = 9)]
        [validateRange(0, 4)]
        [int]$TransportSocket = 0,

        # Specifies whether sockets will be reused or shared. Only valid for TCP or TLS
        [Parameter(Mandatory = $false, Position = 10)]
        [validateSet(0, 1)]
        [int]$ReuseTransport = 1,

        # Specifies the number of minutes that a socket remains connected to the server. 
        # This option is available when ReuseTransport is Enabled. A value of 0 means ReuseTimeout is set Forever*. Otherwise, the valid range is 5-1440
        [Parameter(Mandatory = $false, Position = 11)]
        [validateRange(0, 1440)]
        [int]$ReuseTimeout = 1000,

        # Specifies the protocol to use for sending SIP messages UDP 
        #- Send messages using UDP. 
        #TCP 
        #- Send message using TCP. 
        #TLS 
        #- Send message using TLS.
        [Parameter(Mandatory = $true, Position = 12)]
        [validateRange(0, 9)]
        [int]$Protocol = 1,

        # Specifies the method to monitor server None 
        #- no monitoring of this server occurs 
        #SIP options 
        #- an Options message is sent to the server
        [Parameter(Mandatory = $false, Position = 13)]
        [validateSet(0, 1, 2)]
        [int]$Monitor = 1,

        # Specify frequency in seconds to determine server availability. 
        # This configuration is available when Monitor is set to SIP Options . If Monitor is not set to SIP Options, this value needs to be 0. Otherwise, this value needs to be in the range 30-300*
        [Parameter(Mandatory = $false, Position = 14)]
        [validateRange(0, 300)]
        [int]$KeepAliveFrequency = 30,

        # Specify frequency in seconds to check server to determine whether it has become available. 
        # This configuration is available when Monitor is set to SIP Options . If Monitor is not set to SIP Options, this value needs to be 0. Otherwise, this value needs to be in the range 5-300*
        [Parameter(Mandatory = $false, Position = 15)]
        [validateRange(0, 300)]
        [int]$RecoverFrequency = 5,

        # The local username of the SBC Edge system. 
        # This configuration is available when Monitor is set to SIP Options
        [Parameter(Mandatory = $false, Position = 16)]
        [validateLength(0, 64)]
        [string]$LocalUserName = "Anonymous",

        # The username of SIP server. 
        # This configuration is available when Monitor is set to SIP Options
        [Parameter(Mandatory = $false, Position = 17)]
        [validateLength(0, 64)]
        [string]$PeerUserName = "Anonymous",

        # Specifies the priority of this server. The priority is used to order the server when more than 1 is configured.
        [Parameter(Mandatory = $true, Position = 18)]
        [validateRange(0, 16)]
        [int]$Priority = 0,

        # Specifies a Remote Authorization table for this SIP Server, from a list of authorization tables defined in the Remote Authorization Tables. The Remote Authorization table is used by a Signaling group when a challenge (401/407) is issued by the server. The table contains a realm, user name, and password. There are used to provide credentials to he server issuing the challenge.
        [Parameter(Mandatory = $false, Position = 19)]
        [validateRange(0, 65535)]
        [int]$RemoteAuthorizationTableID = 0,

        # Specifies a Contact Registration Table for this SIP Server,from a list of registration tables defined in the Contact Registrant Tables. The Contact Registration is used by a Signaling Group to register one or more contacts to a registrar. The contact information contains the SIP address of record and the methods which can be used to establish sessions to this Signaling group.
        [Parameter(Mandatory = $false, Position = 20)]
        [validateRange(0, 65535)]
        [int]$ContactRegistrantTableID = 0,

        # If more than one Contact Registrant Entry is in Contact table, stagger Register Requests by 1 second. Applies to UnRegister also. This will only be displayed and applicble if Contact Registract Table is something other than None.
        [Parameter(Mandatory = $false, Position = 21)]
        [validateSet(0, 1)]
        [int]$StaggerRegistration = 0,

        # When enabled, a Register with Expires: 0 will be sent to the SIP Server on power up. After the Unregister (Expires: 0) is complete, a Register (Expires: non-zero) will then be sent.
        [Parameter(Mandatory = $false, Position = 22)]
        [validateSet(0, 1)]
        [int]$ClearRemoteRegistrationOnStartup = 0,

        # Selects whether the Request URI of the incoming request needs to be validated. edsStrict ensures that the request URI is validated, edsLiberal ensures no validation is done.
        [Parameter(Mandatory = $false, Position = 23)]
        [validateSet(0, 1)]
        [int]$SessionURIValidation = 0,

        # If enabled, the following will occur: -Random user values will be generated and put into the Contact-URI of each outgoing Register message. -The random user portion will be saved and compared to incoming Invite Request-Uri's. If the prefix of the R-URI contains SBCxxxx, then if there is a match, SBCxxxx will be stripped and the remaining number used to route (if no match, Invite is not accepted). If there is no SBCxxxx in R-URI, then the number is sent as-is for routing.
        [Parameter(Mandatory = $false, Position = 24)]
        [validateSet(0, 1)]
        [int]$ContactURIRandomizer = 0,

        # This value will only be visible if Remote Authorization Table are defined in SIP Server. When true, if stale=false is received in 401/407, the SBC Edge will set failed retry timer and re-attempt to send Register with same credentials at expiration. When false, if stale=false is received in 401/407, the SBC Edge will never resend a challenged request with the same credentials.(this is RFC behavior)
        [Parameter(Mandatory = $false, Position = 25)]
        [validateSet(0, 1)]
        [int]$RetryNonStaleNonce = 1,

        # If TLS is selected this specifies the TLS profile this server will use for secure SIP messages. 
        # This option is available if Protocol is set to TLS.
        [Parameter(Mandatory = $false, Position = 26)]
        [validateRange(0, 65535)]
        [int]$TLSProfileID = 0,

        # This value will only be visible if both Contact Registrant Table and Remote Authorization Table are defined in SIP Server. When true, the SBC Edge will include authorization headers obtained from previous 401/407 exchange in registration refresh messages. When false, the SBC Edge will not include authorization headers obtained from previous 401/407 exchange in registration refresh messages.
        [Parameter(Mandatory = $false, Position = 27)]
        [validateSet(0, 1)]
        [int]$AuthorizationOnRefresh = 1
		
    )

    # First thing we need to do is get a new TableId
    try {
        if ($uxSession) {
            [int]$sipserverentryid = (get-uxsipservertableentry -uxSipServerTableId $SipServerTableId  -uxSession $uxSession | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | measure-Object -Maximum).Maximum + 1 
        }
        else {
            [int]$sipserverentryid = (get-uxsipservertableentry -uxSipServerTableId $SipServerTableId | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | measure-Object -Maximum).Maximum + 1 
        }
    }
    catch {
        Throw "Unable to get a new entry id"
    }
    

    $args2 = "ServerLookup=$ServerLookup"
    $args2 += "&ServerType=$ServerType"
    $args2 += "&Priority=$Priority"
    $args2 += "&Host=$Hostname"
    $args2 += "&Port=$Port"
    $args2 += "&Protocol=$Protocol"
    $args2 += "&DomainName=$DomainName"
    $args2 += "&Weight=$Weight"
    If ($TLSProfileid) { $args2 += "&TLSProfileID=$TLSProfileid" }
    If ($Monitor) { $args2 += "&Monitor=$Monitor" }
    $args2 += "&ReuseTimeout=$ReuseTimeout"
    $args2 += "&TransportSocket=$TransportSocket"
    
    Write-Verbose "Submitting the following Arguments: $args2"

    $ResourceSplat = @{
        resource      = "sipservertable/$SipServerTableId/sipserver"
        index         = $sipserverentryid
        ReturnElement = "sipserver"
        Arguments     = $args2
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }
    
    Write-Verbose "Submitting Data"
    Write-verbose "Returning the updated table"
    $msg = "Adding A New Entry to sipservertable/$SipServerTableId/sipserver Table on the Gateway with ID $sipserverentryid"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        $Return = new-uxresource @ResourceSplat -WhatIf:$PSBoundParameters.ContainsKey('WhatIf') -Confirm:$false      
    }
    Write-Output $return


}

Function New-UxCallRoutingEntry {
    <#
            .SYNOPSIS      
             This cmdlet creates Call Routing Entries entries in existing Call Routing table
             
            .DESCRIPTION
            This cmdlet creates Call Routing Entries entries in existing Call Routing table.You need to specify the Call Routing table where these Call Routing entries should be created.

                        
            .PARAMETER Parameter Name
                Description

            .PARAMETER ConfigIEState
                Specifies the Administrative State of the resource.

            .PARAMETER TransformationTable
                Sets the Transformation table to use for this call route.

            .PARAMETER RoutePriority
                Priority of the route, 1 is the highest, 10 the lowest. Higher priority routes are matched against before lower priority routes regardless of the order of the routes in the table.

            .PARAMETER CallPriority
                Priority of the call. Used for emergency call identification by dial plan in routing table

            .PARAMETER QualityMetricCalls
                Specifies the number of calls over which the quality metrics are calculated.

            .PARAMETER QualityMetricTime
                Specifies the time in minutes after which a route is tried again after failing quality metrics.

            .PARAMETER QualityMinASRThreshold
                Specifies the minimum answer/seizure ratio for this rule to be considered for use.

            .PARAMETER QualityMaxRoundTripDelayThreshold
                Specifies the maximum average round trip (R/T) delay for this rule to be considered for use.

            .PARAMETER QualityMaxJitterThreshold
                Specifies the maximum average jitter for this rule to be considered for use.

            .PARAMETER QualityMinLQMOSThreshold
                Specifies the minimum average MOS (mean opinion score) value for this rule to be considered for use, in tenths (e.g.: "2.5" is configured as "25"). Setting this value to 0 disables the Minimum MOS threshold. Otherwise, the allowed values are between 10 and 50 (1.0 - 5.0).

            .PARAMETER DestinationType
                Specifies the type of destination for calls.

            .PARAMETER DenyCauseCode
                Specifies the cause code to use for Deny type destionations.

            .PARAMETER MediaSelection
                Specifies the Media List Profile to use for this Call Route.

            .PARAMETER MediaMode
                Determines Audio media mode for SIP calls. Note that when choosing Direct Mode, the valid Video/Application Stream Mode can only be Direct/Disabled.

            .PARAMETER VideoMediaMode
                Determines Video media mode for SIP calls. Note that when choosing Direct Mode, the valid Audio/Fax Stream Mode can only be Direct/Disabled.

            .PARAMETER MediaTranscoding
                Controls whether or not to use Media Transcoding. 
                Transcoding requires a specific Transcoding License. Do not enable Media Transcoding unless your calling configuration requires it and the SBC Edge is licensed for the transcoding feature. If this option is enabled without a trancoding license, a Critical Alarm will be generated even if the calls being routed don't need to be transcoded.

            .PARAMETER CancelOthersUponForwarding
                Controls whether forked calls should clear when one of the forked calls is forwarded.

            .PARAMETER CallForked
                Controls whether to fork a call if this route is selected.

            .PARAMETER ReRouteTable
                Specifies which Cause Code Reroute Table to use. None means no cause code rerouting is used.

            .PARAMETER MessageTranslationTable
                Specifies which Message Translation Table to use. None means no message translation is used.

            .PARAMETER SignalingGroupList
                Specifies the Signaling Groups used as the destination of calls provided as a comma-separated string of the Signaling Group IDs. Not applicable when the Destination Type is Deny or Trunk Group.

            .PARAMETER Description
                Describes the Call Route Table Entry so that it is easily identifiable when re-sequencing Entries.

            .PARAMETER MaximumCallDuration
                Specifies the maximum duration that a call can stay connected in minutes. A zero value will disable this timer.

            .PARAMETER TimeOfDay
                Specifies which Time Of Day restrictions apply to this call route. None means there is no time of day restriction.



            .EXAMPLE
                get-uxtransformationtable    
                
                Assume you want to create a new transformation table.
                First determine the ID of the transformation table in which you want to create the new transformation entry.
                
            .EXAMPLE                
                new-uxtransformationentry -TransformationTableId 6 -InputFieldType 0 -InputFieldValue '^(2([45]\d{2}|6[0-5]\d))$' -OutputFieldType 0 -OutputFieldValue '+44123456\1' -Description "ExtToDDI"
            
                This example creates an Optional (default) transformation entry converting Called Number range  2400 - 2659  to Called Number +44123456XXXX
                
                
            
            .EXAMPLE
                new-uxtransformationentry -TransformationTableId 3 -InputFieldType 3 -InputFieldValue '00(44\d(.*))' -OutputFieldType 3 -OutputFieldValue '+\1' -Description "UKCLIToE164"    
            
                This example creates an Optional transformation entry converting Calling Number beginning with 0044xxxxxx to Calling Number +44xxxxxx
                
                
                
            .EXAMPLE
                new-uxtransformationentry -TransformationTableId 9 -InputFieldType 3 -InputFieldValue '(.*)' -OutputFieldType 3 -OutputFieldValue '\1' -Description "PassthroughCLI" -MatchType 0    
            
                This example creates a Mandatory CLI (Calling Number)passthrough
                
                
            
            .LINK
                For Input/Output Field Value Code mappings, please refer to http://bit.ly/SBC-TransfomationCodes
            
            #>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 20)]
        [PSCustomObject]$uxSession,
        
        # Sets the Transformation table to use for this call route.
        [Parameter(Mandatory = $true, Position = 0)]
        [validateRange(0, 65534)]
        [int]$CallRoutingTable,

        # Specifies the Administrative State of the resource.
        [Parameter(Mandatory = $false, Position = 1)]
        [Alias('Enabled')]
        [validateRange(0, 1)]
        [int]$ConfigIEState = 0,

        # Sets the Transformation table to use for this call route.
        [Parameter(Mandatory = $false, Position = 2)]
        [validateRange(0, 65534)]
        [int]$TransformationTable = 1,

        # Priority of the route, 1 is the highest, 10 the lowest. Higher priority routes are matched against before lower priority routes regardless of the order of the routes in the table.
        [Parameter(Mandatory = $false, Position = 3)]
        [validateRange(1, 10)]
        [int]$RoutePriority = 1,

        # Priority of the call. Used for emergency call identification by dial plan in routing table
        [Parameter(Mandatory = $false, Position = 4)]
        [validateRange(0, 3)]
        [int]$CallPriority = 1,

        # Specifies the number of calls over which the quality metrics are calculated.
        [Parameter(Mandatory = $false, Position = 5)]
        [validateRange(1, 100)]
        [int]$QualityMetricCalls = 10,

        # Specifies the time in minutes after which a route is tried again after failing quality metrics.
        [Parameter(Mandatory = $false, Position = 6)]
        [validateRange(1, 60)]
        [int]$QualityMetricTime = 10,

        # Specifies the minimum answer/seizure ratio for this rule to be considered for use.
        [Parameter(Mandatory = $false, Position = 7)]
        [validateRange(0, 100)]
        [int]$QualityMinASRThreshold = 0,

        # Specifies the maximum average round trip (R/T) delay for this rule to be considered for use.
        [Parameter(Mandatory = $false, Position = 8)]
        [validateRange(0, 65535)]
        [int]$QualityMaxRoundTripDelayThreshold = 65535,

        # Specifies the maximum average jitter for this rule to be considered for use.
        [Parameter(Mandatory = $false, Position = 9)]
        [validateRange(0, 3000)]
        [int]$QualityMaxJitterThreshold = 3000,

        # Specifies the minimum average MOS (mean opinion score) value for this rule to be considered for use, in tenths (e.g.: "2.5" is configured as "25"). Setting this value to 0 disables the Minimum MOS threshold. Otherwise, the allowed values are between 10 and 50 (1.0 - 5.0).
        [Parameter(Mandatory = $false, Position = 10)]
        [validateRange(0, 50)]
        [int]$QualityMinLQMOSThreshold = 0,

        # Specifies the type of destination for calls.
        [Parameter(Mandatory = $false, Position = 11)]
        [validateRange(0, 3)]
        [int]$DestinationType = 0,

        # Specifies the cause code to use for Deny type destionations.
        [Parameter(Mandatory = $false, Position = 12)]
        [validateRange(0, 127)]
        [int]$DenyCauseCode = 16,

        # Specifies the Media List Profile to use for this Call Route.
        [Parameter(Mandatory = $false, Position = 13)]
        [validateRange(0, 65534)]
        [int]$MediaSelection = 0,

        # Determines Audio media mode for SIP calls. Note that when choosing Direct Mode, the valid Video/Application Stream Mode can only be Direct/Disabled.
        [Parameter(Mandatory = $false, Position = 14)]
        [validateRange(0, 5)]
        [int]$MediaMode = 0,

        # Determines Video media mode for SIP calls. Note that when choosing Direct Mode, the valid Audio/Fax Stream Mode can only be Direct/Disabled.
        [Parameter(Mandatory = $false, Position = 15)]
        [validateRange(0, 2)]
        [int]$VideoMediaMode = 0,

        # Controls whether or not to use Media Transcoding. 
        [Parameter(Mandatory = $false, Position = 16)]
        [validateRange(0, 1)]
        [int]$MediaTranscoding = 0,

        # Controls whether forked calls should clear when one of the forked calls is forwarded.
        [Parameter(Mandatory = $false, Position = 17)]
        [validateRange(0, 1)]
        [int]$CancelOthersUponForwarding = 0,

        # Controls whether to fork a call if this route is selected.
        [Parameter(Mandatory = $false, Position = 18)]
        [validateRange(0, 1)]
        [int]$CallForked = 0,

        # Specifies which Cause Code Reroute Table to use. None means no cause code rerouting is used.
        [Parameter(Mandatory = $false, Position = 19)]
        [validateRange(0, 65534)]
        [int]$ReRouteTable = 0,

        # Specifies which Message Translation Table to use. None means no message translation is used.
        [Parameter(Mandatory = $false, Position = 20)]
        [validateRange(0, 65534)]
        [int]$MessageTranslationTable = 0,

        # Specifies the Signaling Groups used as the destination of calls provided as a comma-separated string of the Signaling Group IDs. Not applicable when the Destination Type is Deny or Trunk Group.
        [Parameter(Mandatory = $false, Position = 21)]
        [validateRange(0, 40)]
        [string]$SignalingGroupList = "1",

        # Describes the Call Route Table Entry so that it is easily identifiable when re-sequencing Entries.
        [Parameter(Mandatory = $false, Position = 22)]
        [ValidateLength(0, 64)]
        [String]$Description,

        # Specifies the maximum duration that a call can stay connected in minutes. A zero value will disable this timer.
        [Parameter(Mandatory = $false, Position = 23)]
        [validateRange(0, 10080)]
        [int]$MaximumCallDuration = 0,

        # Specifies which Time Of Day restrictions apply to this call route. None means there is no time of day restriction.
        [Parameter(Mandatory = $false, Position = 24)]
        [validateRange(0, 65534)]
        [int]$TimeOfDay = 0
                
    )
    # First thing we need to do is get a new EntryId for the entry
    # DEPENDENCY ON get-uxtransformationentry FUNCTION TO GET THE NEXT AVAILABLE TRANSFORMATIONTABLEID
    try {
        if ($uxSession) {
            [int]$NewUxCallRoutingEntry = (Get-UxCallRoutingEntry -CallRoutingTableId $CallRoutingTable -uxSession $uxSession -verbose:$false | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | Measure-Object -Maximum).Maximum + 1 
        }
        else {
            [int]$NewUxCallRoutingEntry = (Get-UxCallRoutingEntry -CallRoutingTableId $CallRoutingTable -verbose:$false | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | Measure-Object -Maximum).Maximum + 1 
        }
    }
    catch {
        Throw "Command failed when trying to execute the UxCallRoutingEntry using `"get-UxCallRoutingEntry`" cmdlet.The error is $_"
    }

    $NewPSObject = [PSCustomObject]@{
        PSTypeName = 'SBC.Object'
    }

      
    Write-Verbose "Adding as table number $NewUxCallRoutingEntry"

    $parametersList = $($MyInvocation.MyCommand.Parameters.Keys)[1..25]
    # We limit the keys to exclude uxSession and the standard advanved cmdlets parameters with [1..25]
    foreach ($parameter in $parametersList ) {
        $Value = (Get-Variable $parameter -ea SilentlyContinue).value
        $NewPSObject | Add-Member -MemberType NoteProperty -Name $parameter -Value $Value
    }
    
    $ReturnTransformationTable = Get-UxTransformationTable -Verbose:$false | Where-Object { $_.id -eq $NewPSObject.TransformationTable }
    Write-verbose "Using Transformation Table $($ReturnTransformationTable.Description)"

    $ReturnReRoutingTable = Get-UxReRouteTable -Verbose:$false | Where-Object { $_.id -eq $NewPSObject.ReRouteTable }
    Write-verbose "Using ReRouting Table $($ReturnReRoutingTable.Description)"



    $SignalingGroups = Get-UxSignalGroup -Verbose:$false
    $SipSignalIDList = $SignalingGroupList.split(",")
    $i = 1
    ForEach ($SignalID in $SipSignalIDList ) {
        $ReturnSignalingTable = $SignalingGroups | Where-Object { $_.id -eq $SignalID }
        Write-verbose "Using Signaling Groups in order [$i] $($ReturnSignalingTable.Description)"
        $i ++
    }

    # Now We have built the object We need to get it into html format
    $Arguments = (New-UxURLandPSObject $NewPSObject).htmlstr

    $ResourceSplat = @{
        resource      = "routingtable/$CallRoutingTable/routingentry"
        index         = $NewUxCallRoutingEntry
        ReturnElement = "routingentry_list"
        Arguments     = $Arguments
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }


    Write-Verbose "Submitting Data"
    Write-verbose "Returning the updated table"
    $msg = "Adding A New Entry to Transformation Table on the Gateway with ID $NewUxCallRoutingEntry"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        $Return = new-uxresource @ResourceSplat -WhatIf:$PSBoundParameters.ContainsKey('WhatIf') -Confirm:$false      
    }
    Write-Output $return.routingtable_list


}


Function Get-uxTableToParameter {
    <#
    .SYNOPSIS      
        A small helper function which parses the Ribbon Wiki to create a list of parameters
        
    .DESCRIPTION
        Creating a parameter list is a pain in the ass, so i created a small function that will query the wiki and copy a parameter list to the clip board
        Just pass the wiki page you want it to create a parameter list from


        
    #>        
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        # Pass the page of the SBC wiki entry - We make the assumption that it is the second table
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$Page = "https://support.sonus.net/display/UXAPIDOC/Resource+-+routingentry",
        [Parameter(Mandatory = $false, Position = 1)]
        [switch]$helpsection,
        [Parameter(Mandatory = $false, Position = 2)]
        [switch]$listWDefaults
    )
    # $ParsedPage = Invoke-WebRequest "https://support.sonus.net/display/UXAPIDOC/Resource+-+routingentry"
    $ParsedPage = Invoke-WebRequest $page
    $Table = $ParsedPage.ParsedHtml.getElementsByTagName('TABLE')[1]
    $count = -1;
    $Table.rows | ForEach-Object {
        $count = $count + 1
        if ($listWDefaults) {
            $str = "{0} = {1}," -f $_.cells[0].innertext.trim(), $_.cells[4].innertext.trim()
            Write-output $str
        }
        else {
            if ($helpsection) {
                Write-Output ""
                Write-output ".PARAMETER $($_.cells[0].innertext.trim())"
                Write-output "    $($_.cells[6].innertext.trim())"
            }
            else {
                $type = $_.cells[3].innertext.trim()

                Write-Output ""
                Write-output "`# $($_.cells[6].innertext.trim())"
                If ( $($_.cells[1].innertext.trim()) -eq "Yes") {
                    $Mandatory = "true" 
                }
                else {
                    $Mandatory = "false" 
                }
                Write-output "[Parameter(Mandatory=`$$Mandatory,Position=$count)]"
                If ( $($_.cells[5].innertext.trim()) -like "*Max Length*") {
                    Write-output "[validateLength(0,256)]"
                }
                elseif ($type -eq "enum") {
                    
                    Write-output "[validateSet(0,10)]"
                }
                else {
                    Write-output "[validateRange(0,65535)]"
                }
                
                
                if ($type -eq "enum") { $newtype = "int" } else { $newtype = $type }
                $str = "[{2}]`${0} = {1}," -f $_.cells[0].innertext.trim(), $_.cells[4].innertext.trim(), $newtype
                Write-output $str            
            }
        }
        

        
    }
    
    
        
        
}


Function New-UxCallRoutingTable {
    <#
	.SYNOPSIS      
	 This cmdlet creates a new Call Routing Table (not routing table entry)
	 
	.DESCRIPTION
	This cmdlet creates a new Call Routing Table (not routing table entry)
	
	.PARAMETER Description
	Enter here the Description (Name) of the Call Routing table.This is what will be displayed in the Ribbon GUI
	
	.EXAMPLE
	 new-UxCallRoutingTable -Description "LyncToPBX"
	
        #>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #Description of the new tablle
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateLength(1, 64)]
        [string]$Description
    )
        

    # First thing we need to do is get a new TableId
    try {
        if ($uxSession) {
            [int]$NewCallRoutingTableId = (get-UxCallRoutingTable -uxSession $uxSession | select-object -ExpandProperty id | Measure-Object -Maximum).Maximum + 1 
        }
        else {
            [int]$NewCallRoutingTableId = (get-UxCallRoutingTable | select-object -ExpandProperty id | Measure-Object -Maximum).Maximum + 1 
        }
    }
    catch {
        Throw "Unable to get a new table id"
    }

    #Lets create the information to upload, this nees to be in HTTP format for the PUT
    $HTTPDescription = "Description=$Description"

    $ResourceSplat = @{
        resource      = "routingtable"
        index         = $NewCallRoutingTableId
        ReturnElement = "routingtable_list"
        Arguments     = $HTTPDescription
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    Write-Verbose "Submitting Data"
    Write-verbose "Returning the updated table"
    $msg = "Adding A New Entry to Transformation Table on the Gateway with ID $NewCallRoutingTableId"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        $Return = new-uxresource @ResourceSplat -WhatIf:$PSBoundParameters.ContainsKey('WhatIf') -Confirm:$false      
    }
    Write-Output $return.routingtable_list

}

Function Get-UxCallRoutingTable {
    <#
	.SYNOPSIS      
	 This cmdlet displays all the sipprofile names and ID's

    .EXAMPLE
	 get-UxSipProfile
	   
    .EXAMPLE
    $Creds = Get-credential
	$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
	get-UxSipProfile -uxSession $Obj

	#>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #If you want to filter send a profile id.
        [Parameter(Mandatory = $false, Position = 0)]
        [int]$CallRoutingTableId
        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    $ResourceSplat = @{
        resource      = "routingtable"
        ReturnElement = "routingtable_list"
        detail        = $true
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }
    $TopLevel = (get-uxresource @ResourceSplat).routingtable

    if ($CallRoutingTableId) {
        $ResourceSplat = @{
            resource      = "routingtable/$CallRoutingTableId/routingentry"
            ReturnElement = "routingentry_list"
            detail        = $true
        }
        if ($uxSession) { $ResourceSplat.uxSession = $uxSession }    
        $SubLevel = (get-uxresource @ResourceSplat).routingentry

        $Seq = $TopLevel | Where-Object { $_.id -eq $CallRoutingTableId } | Select-Object -ExpandProperty Sequence
        $OrderedList = Get-UxOrderedList -Sequence $Seq -List $SubLevel
    

        # Lets Build a Temp object where we can store the top level then the entires.
        #$TempReturn = [PSCustomObject]@{
        #    Table   = $TopLevel | Where-Object { $_.id -eq $CallRoutingTableId }
        #    Entries = $OrderedList
        #}
        
        
        # Lets Finally Build the Return Object 
        return $OrderedList
    }
    else {
        return $TopLevel
    }
 
}

Function Get-UxReRouteTable {
    <#
	.SYNOPSIS      
	 This cmdlet displays all the sipprofile names and ID's

    .EXAMPLE
	 get-UxSipProfile
	   
    .EXAMPLE
    $Creds = Get-credential
	$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
	get-UxSipProfile -uxSession $Obj

	#>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #If you want to filter send a profile id.
        [Parameter(Mandatory = $false, Position = 0)]
        [int]$ReRoutingTableId
        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    $ResourceSplat = @{
        resource      = "reroutetable"
        ReturnElement = "reroutetable_list"
        detail        = $true        
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }
    $TopLevel = (get-uxresource @ResourceSplat).reroutetable

    if ($ReRoutingTableId) {
        $ResourceSplat = @{
            resource      = "reroutetable/$CallRoutingTableId"
            ReturnElement = "reroutetable_list"
            detail        = $true
        }
        if ($uxSession) { $ResourceSplat.uxSession = $uxSession }    
        $SubLevel = (get-uxresource @ResourceSplat).reroutetable

        $Seq = $TopLevel | Where-Object { $_.id -eq $CallRoutingTableId } | Select-Object -ExpandProperty Sequence
        $OrderedList = Get-UxOrderedList -Sequence $Seq -List $SubLevel
    

        # Lets Build a Temp object where we can store the top level then the entires.
        #$TempReturn = [PSCustomObject]@{
        #    Table   = $TopLevel | Where-Object { $_.id -eq $CallRoutingTableId }
        #    Entries = $OrderedList
        #}
        
        
        # Lets Finally Build the Return Object 
        return $OrderedList
    }
    else {
        return $TopLevel
    }
 
}


Function Get-UxCallRoutingEntry {
    <#
	.SYNOPSIS      
	 This cmdlet reports The Transformation from Ribbon SBC.
	 
	.DESCRIPTION
     Gets all the entries but in an unordered form. As the sequence is stored at the level above 
     use get-UxTransformationTable 'TableID' to get ordered list as per sequence.
	
	.EXAMPLE
	get-uxtransformationEntry -uxTransformationTableId 4
    
    .EXAMPLE
    $Creds = Get-credential
	$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
	get-uxtransformationtable -uxSession $Obj -uxTransformationTableId 4

	#>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #To find the ID of the transformation table execute "get-uxtransformationtable" cmdlet'
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$CallRoutingTableId

        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    $ResourceSplat = @{
        resource      = "routingtable/$CallRoutingTableId/routingentry"
        ReturnElement = "routingentry_list"
        Details       = $true
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }


    #Further filtering of the object for this option - Here we want to see the whole details of the object.
    $Return = get-uxresource @ResourceSplat
    Write-Output $return.routingentry
    
}





#Function to get sipprofile
Function Get-UxSipProfile {
    <#
	.SYNOPSIS      
	 This cmdlet displays all the sipprofile names and ID's

    .EXAMPLE
	 get-UxSipProfile
	   
    .EXAMPLE
    $Creds = Get-credential
	$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
	get-UxSipProfile -uxSession $Obj

	#>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #If you want to filter send a profile id.
        [Parameter(Mandatory = $false, Position = 0)]
        [int]$sipprofileid
        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    if ($sipprofileid) {
        $ResourceSplat = @{
            resource = "sipprofile/$sipprofileid"
            #ReturnElement = "sipprofile"
            detail   = $true
        }    
    }
    else { 
        $ResourceSplat = @{
            resource      = "sipprofile"
            ReturnElement = "sipprofile_list"
            detail        = $true
        }
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    #Further filtering of the object for this option - Here we want to see the whole details of the object.
    $Return = get-uxresource @ResourceSplat
    Write-Output $return.sipprofile
 
}

#Function to get sipserver table entries from a specified sipserver table
Function Get-UxSipServerTableEntry {
    <#
	.SYNOPSIS      
	 This cmdlet displays the sipserver table entries of a specified sipserver table.
	 
	.DESCRIPTION
	This cmdlet displays the sipserver table entries if a sipserver table id is specified. To extract the sipserver table id execute "get-uxsipservertable" cmdlet
	The output of the cmdlet contains InputField/OutputFields which are displayed as integer. To map the numbers to friendly names refer: bit.ly/Iy7JQS
	
	.PARAMETER uxsipservertableid
	Enter here the sipserver table id of the sipserver table.To extract the sipserver table id execute "get-uxsipservertable" cmdlet
	
	.EXAMPLE
	 get-uxsipservertableentry -uxsipservertableid 4
	
    #>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #To find the ID of the sipserver table execute "get-uxsipservertable" cmdlet
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$uxSipServerTableId

        
    )
  

    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    $ResourceSplat = @{
        resource      = "sipservertable/$uxSipServerTableId/sipserver"
        ReturnElement = "sipserver_list"
        Details       = $true
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }


    #Further filtering of the object for this option - Here we want to see the whole details of the object.
    $Return = get-uxresource @ResourceSplat
    Write-Output $return.sipserver

}

Function New-UxSipProfile {
    <#
	.SYNOPSIS      
	 This cmdlet creates a new sip profile (not sipserver table entry)
	 
	.DESCRIPTION
	This cmdlet creates a sip profile (not sipserver table entry).
	
	.PARAMETER Description
	Enter here the Description (Name) of the sipserver table.This is what will be displayed in the Ribbon GUI
	
	.EXAMPLE
	 new-uxsipservertable -Description "LyncToPBX"
	
	#>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession,
        
        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateLength(1, 64)]
        [string]$Description,

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateLength(1, 255)]
        [string]$StaticHost ,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateLength(1, 64)]
        [string]$OriginFieldUserName ,

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateRange(0, 3)]
        [int]$FQDNinFromHeader,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateRange(0, 3)]
        [int]$FQDNinContactHeader 


    )
        

    # First thing we need to do is get a new TableId
    try {
        if ($uxSession) {
            [int]$sipprofileid = (get-uxsipprofile -uxSession $uxSession | Select-Object -ExpandProperty id | measure-Object -Maximum).Maximum + 1 
        }
        else {
            [int]$sipprofileid = (get-uxsipprofile | Select-Object -ExpandProperty id | measure-Object -Maximum).Maximum + 1 
        }
    }
    catch {
        Throw "Unable to get a new table id"
    }
    
	
    #URL for the new sipserver table
    $args1 = "Description=$Description"
    If ($statichost) { $args1 += "&StaticHost=$StaticHost" }
    If ($OriginFieldUserName) { $args1 += "&OriginFieldUserName=$OriginFieldUserName" }
    If ($FQDNinFromHeader) { $args1 += "&FQDNinFromHeader=$FQDNinFromHeader" }
    If ($FQDNinContactHeader) { $args1 += "&FQDNinContactHeader=$FQDNinContactHeader" }

    $ResourceSplat = @{
        resource      = "sipprofile"
        index         = $sipprofileid
        ReturnElement = "sipprofile"
        Arguments     = $args1
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    Write-Verbose "Submitting Data"
    Write-verbose "Returning the updated table"
    $msg = "Adding A New Entry to sipprofile Table on the {0} Gateway with ID {1}" -f $uxSession.host , $sipprofileid
    if ($PSCmdlet.ShouldProcess($($msg))) {
        $Return = new-uxresource @ResourceSplat -WhatIf:$PSBoundParameters.ContainsKey('WhatIf') -Confirm:$false      
    }
    Write-Output $return

}

#Function to get signalgroup
Function Get-UxSignalGroup {
    <#
	.SYNOPSIS      
	    This cmdlet displays all the signalgroup names and ID's
    
    .DESCRIPTION
        This cmdlet can be used to pull either the how signalling group or an individual entry by passing the signaling group id.

	.EXAMPLE
        get-UxSignalGroup

        This pulls all the signaling groups from the last connected box.

    .EXAMPLE
        get-UxSignalGroup 2

        This pulls the individual signal group.
	   
    .EXAMPLE
        $Creds = Get-credential

        PS C:\>$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
        
        PS C:\>get-UxSignalGroup -uxSession $Obj

        This Example uses the uxSession object to pull entries just from that session rather than the last default session.

	#>
    
    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,
        #If you want to filter send a group id.
        [Parameter(Mandatory = $false, Position = 0)]
        [int]$signalgroupid
        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    if ($signalgroupid) {
        $ResourceSplat = @{
            resource = "sipsg/$signalgroupid"
            #ReturnElement = "sipsg"
            detail   = $true
        }    
    }
    else { 
        $ResourceSplat = @{
            resource      = "sipsg"
            ReturnElement = "sipsg_list"
            detail        = $true
        }
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    #Further filtering of the object for this option - Here we want to see the whole details of the object.
    $Return = get-uxresource @ResourceSplat
    Write-Output $return.sipsg


}

Function New-UxURLandPSObject {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline)]
        $Object
    )
    $NewPSObject = [PSCustomObject]@{
        PSTypeName = 'SBC.Object'
    }
    ForEach ($Prop in $($Object | Get-Member -MemberType Properties | Select-object -exp name) ) {
        $Str += "{0}={1}&" -f $prop, $Object.$Prop
        $NewPSObject | Add-Member -MemberType NoteProperty -Name $Prop -Value $Object.$Prop
        
    }
    # Lets remove the last '&' character
    $NewPSObject = [PSCustomObject]@{
        Posh    = $NewPSObject
        HtmlStr = $($str.Substring(0, $Str.Length - 1)).replace("+", '%2B')
    } 
    Return $NewPSObject

}


#Function to create new signalgroup
Function New-UxSignalGroup {
    <#
	.SYNOPSIS      
	 This cmdlet creates a new signalgroup
	 
	.DESCRIPTION
	This cmdlet creates a sip new signalgroup
	
	.PARAMETER Description
	Enter here the Description (Name) of the sipserver table.This is what will be displayed in the Ribbon GUI
	
	.EXAMPLE
	 new-uxsignalgroup -Description "LyncToPBX"
	
	#>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        [Parameter(Mandatory = $false, Position = 20)]
        [PSCustomObject]$uxSession,

        [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'Short description/name of the SG')]
        [ValidateLength(1, 64)]
        [string]$Description ,

        [Parameter(Mandatory = $false, Position = 1, HelpMessage = 'Enable or Disable this signaling group')]
        [ValidateSet(0, 1)]
        [int]$CustomAdminState = 1 ,

        [Parameter(Mandatory = $true, Position = 1, HelpMessage = 'Specifies the SIP Profile to#> be used by this Signaling Group')]
        [ValidateRange(1, 65534)]
        [int]$ProfileID ,
        
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = 'Specifies the SIP Server Table to be used by this Signaling Group')]
        [ValidateRange(1, 65534)]
        [int]$ServerClusterId ,

        [Parameter(Mandatory = $true, Position = 2, HelpMessage = 'Specifies the number of SIP channels available for call')]
        [ValidateRange(1, 960)]
        [int]$Channels = 10 ,

        [Parameter(Mandatory = $true, Position = 3, HelpMessage = 'Specifies the Media List to be used by this Signaling Group')]
        [ValidateRange(1, 65534)]
        [int]$MediaConfigID ,

        [Parameter(Mandatory = $true, Position = 4, HelpMessage = 'Specifies the Call Routing Table to be used by this Signalling Group')]
        [ValidateRange(1, 65534)]
        [int]$RouteTableID ,

        [Parameter(Mandatory = $false, Position = 5, HelpMessage = 'Specifies the local listen port 1 on which SG can receive message. This needs to be provided if Protocol_1 is present')]
        [ValidateRange(0, 65535)]
        [int]$ListenPort_1 = 5067 ,

        [Parameter(Mandatory = $false, Position = 6, HelpMessage = 'Protocol type used by the listener. Currently only 1 (UDP),2 (TCP) and 4 (TLS) are being used. This needs to be provided if ListenPort_1 is present')]
        [ValidateRange(0, 9)]
        [int]$Protocol_1 = 2 ,

        [Parameter(Mandatory = $false, Position = 7, HelpMessage = 'If protocol is TLS this is the id of TLS profile in use')]
        [ValidateRange(0, 65534)]
        [int]$TLSProfileID_1 ,

        [Parameter(Mandatory = $true, Position = 8, HelpMessage = 'Specifies the interface name followed by -1 for primary, followed by -2 for secondary IP')]
        [ValidateLength(7, 60)]
        [string]$NetInterfaceSignaling ,

        [Parameter(Mandatory = $false, Position = 9, HelpMessage = 'Comma separated list of remote IPs or subnet from which SG can receive requests')]
        [ValidateLength(7, 2500)]
        [string]$RemoteHosts ,

        [Parameter(Mandatory = $false, Position = 10, HelpMessage = 'Comma separated list of subnet masks for the IP Addresses specified in RemoteHosts above')]
        [ValidateLength(7, 2500)]
        [string]$RemoteMasks = "255.255.255.255" 
	

    )


    # First thing we need to do is get a new TableId
    try {
        if ($uxSession) {
            [int]$newSipSigid = (get-uxsignalgroup -uxSession $uxSession | Select-Object -ExpandProperty id | measure-Object -Maximum).Maximum + 1 
        }
        else {
            [int]$newSipSigid = (get-uxsignalgroup | Select-Object -ExpandProperty id | measure-Object -Maximum).Maximum + 1 
        }
    }
    catch {
        Throw "Unable to get a new Signaling Group ID"
    }


    #Setting required variables
    $RelOnQckConnect = 0
    $RTPMode = 1
    $RTPProxyMode = 1
    $RTPDirectMode = 1
    $VideoProxyMode = 0
    $VideoDirectMode = 0
    $HuntMethod = 4
    $ProxyIpVersion = 0
    $DSCP = 40
    $NATTraversalType = 0
    $ICESupport = 0
    $ICEMode = 0
    $InboundNATTraversalDetection = 0
    <#
    #Default for non required parameters
    $ServerSelection = 0
    $RelOnQckConnectTimer = 1000
    $ToneTableID = 0
    $ActionSetTableID = 0
    $RingBack = 0
    $Direction = 2
    $PlayCongestionTone = 0
    $Early183 = 0
    $AllowRefreshSDP = 1
    $OutboundProxy = ""
    $OutboundProxyPort = 5060
    $NoChannelAvailableId = 34
    $TimerSanitySetup = 180000
    $TimerCallProceeding = 180000
    $ChallengeRequest = 0
    $NotifyCACProfile = 0
    $NonceLifetime = 600
    $Monitor = 2
    $AuthorizationRealm = ""
#>


    #Signalling ID Parameters

    $args1 = "Description=$Description"
    If ($customadminstate) { $args1 += "&customadminstate=$customadminstate" }
    If ($ProfileID) { $args1 += "&profileid=$ProfileID" }
    If ($channels) { $args1 += "&channels=$channels" }
    If ($mediaconfigid) { $args1 += "&mediaconfigid=$mediaconfigid" }
    If ($routetableid) { $args1 += "&routetableid=$routetableid" }
    If ($ListenPort_1) { $args1 += "&ListenPort_1=$ListenPort_1" }
    If ($Protocol_1) { $args1 += "&Protocol_1=$Protocol_1" }
    If ($TLSProfileID_1) { $args1 += "&TLSProfileID_1=$TLSProfileID_1" }
    If ($netinterfacesignaling) { $args1 += "&netinterfacesignaling=$netinterfacesignaling" }
    If ($remotehosts) { $args1 += "&remotehosts=$remotehosts" }
    If ($remotemasks) { $args1 += "&remotemasks=$remotemasks" }
    If ($relonqckconnect) { $args1 += "&relonqckconnect=$relonqckconnect" }
    If ($rtpmode) { $args1 += "&rtpmode=$rtpmode" }
    If ($rtpproxymode) { $args1 += "&rtpproxymode=$rtpproxymode" }
    If ($rtpdirectmode) { $args1 += "&rtpdirectmode=$rtpdirectmode" }
    If ($videoproxymode) { $args1 += "&videoproxymode=$videoproxymode" }
    If ($videodirectmode) { $args1 += "&videodirectmode=$videodirectmode" }
    If ($huntmethod) { $args1 += "&huntmethod=$huntmethod" }
    If ($proxyipversion) { $args1 += "&proxyipversion=$proxyipversion" }
    If ($dscp) { $args1 += "&dscp=$dscp" }
    If ($nattraversaltype) { $args1 += "&nattraversaltype=$nattraversaltype" }
    If ($icesupport) { $args1 += "&icesupport=$icesupport" }
    If ($inboundnattraversaldetection) { $args1 += "&inboundnattraversaldetection=$inboundnattraversaldetection" }
    If ($icemode) { $args1 += "&icemode=$icemode" }

     

    # Okay Lets Build the Spalt
    $ResourceSplat = @{
        resource      = "sipsg"
        index         = $newSipSigid
        ReturnElement = "sipsg"
        Arguments     = $args1
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }

    Write-Verbose "Submitting Data"
    Write-verbose "Returning the updated table"
    $msg = "Adding A New Entry to SipSignaling Table on the Gateway with ID $newSipSigid"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        $Return = new-uxresource @ResourceSplat -WhatIf:$PSBoundParameters.ContainsKey('WhatIf') -Confirm:$false      
    }
    Write-Output $return
}

#Function to restartUX
Function Restart-UxGateway {
    <#
	.SYNOPSIS      
	 This cmdlet restarts Ribbon gateway
	 
	.SYNOPSIS      
	This cmdlet restarts Ribbon gateway
	
	.EXAMPLE
	 restart-uxgateway
	
	#>

    [cmdletbinding()]
    Param(
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession = $DefaultSession
    )
  
    $Status = Send-UxCommand -uxSession $uxSessionObj -Command reboot -ReturnElement status
    If ($status.http_code -eq "200") {
        Write-Output "Reboot initiated and completed succesfully" 
    }
}

