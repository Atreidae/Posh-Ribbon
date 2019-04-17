<#
    .SYNOPSIS 
      RibbonSBCEdge Powershell module allows access to Ribbon SBC Edge via PowerShell using REST API's.
	 
	.DESCRIPTION
	  
	  For the module to run correctly following pre-requisites should be met:
	  1) PowerShell v4.0
	  2) Ribbon SBC Edge on R3.0 or higher
	  3) Create REST logon credentials (http://www.allthingsuc.co.uk/accessing-sonus-ux-with-rest-apis/)
    
      Once you have created the account use help Connect-UxGateway to get started.
	 
	.NOTES
		Name: RibbonEdge
        V2 Author: Chris Burns (GCIcom)
        V1 Author: Vikas Jaswal (Modality Systems Ltd)
		Additional cmdlets added by: Kjetil Lindløkken
        Additional cmdlets added by: Adrien Plessis
        
		
		Version History:
		Version 1.0 - 30/11/13 - Module Created - Vikas Jaswal
		Version 1.1 - 03/12/13 - Added new-ux*, restart-ux*, and get-uxresource cmdlets - Vikas Jaswal
		Version 1.2 - 02/10/16 - Added get-uxsipservertable, new-uxsippservertable cmdlets - Kjetil Lindløkken
		Version 1.3 - 02/10/18 - Added get-uxsipprofile, Get-uxsipprofileid, get-uxsipservertableentry cmdlets - Kjetil Lindløkken
		Version 1.4 - 03/10/18 - Added new-uxsipserverentry cmdlet - Kjetil Lindløkken
		Version 1.5 - 03/10/18 - Added optional parameter to the get-uxsipprofile cmdlet to add id directly - Kjetil Lindløkken
		Version 1.6 - 04/10/18 - Added new-uxsipprofile cmdlet - Kjetil Lindløkken
		Version 1.7 - 20/12/18 - Match Ribbon rebranding, Update link to Ribbon Docs - Adrien Plessis
		Version 2.0 - 15/04/19 - Rewrite for modern module design. And better use of [XML] accelerator and details switch. - Chris Burns
		
		Please use the script at your own risk!
	
    .LINK
        http://www.posh.dev
		http://www.allthingsuc.co.uk
     
  #>



Function Connect-UxGateway {
    <#
	.SYNOPSIS      
	 This cmdlet connects to the Ribbon SBC and extracts the session token.
	 
	.DESCRIPTION
	This cmdlet connects to the Ribbon SBC and extracts the session token required for subsequent cmdlets.All other cmdlets will fail if this command is not successfully executed.
	
	.PARAMETER uxhostname
	Enter here the hostname or IP address of the Ribbon SBC
	
	.PARAMETER credentials
	Pass a secure credential to the cmdlet, this should be your REST API credentials.
	
	
	.EXAMPLE
	$Creds = Get-credential
	connect-uxgateway -uxhostname 1.1.1.1 -Credentials $Creds
	
	.EXAMPLE
	$Creds = Get-credential
	connect-uxgateway -uxhostname lyncsbc01.allthingsuc.co.uk -Credentials $Creds

	.OUTPUT
	The cmdlet will return a web session variable which can be stored and used with multiple cmdlets.
	
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
        host        = $uxhostname
        session     =	$Session
        credentials = $Credentials
    }

    return [PSCustomObject]@{
        host        =	$uxhostname
        session     =	$Session
        credentials = $Credentials
    }
    
}


#Function to grab SBC Edge system information
Function Get-UxSystemInfo {
    <#
	.SYNOPSIS      
	 This cmdlet collects System information from Ribbon SBC.
	
	.EXAMPLE
	$Creds = Get-credential
	$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
	get-uxSystemInfo -uxSession $obj
	
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
	$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
	get-uxsystemcallstats -uxSession $Obj

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
	 This cmdlet reports Call statistics from Ribbon SBC.
	 
	.DESCRIPTION
	 This cmdlet report Call statistics (global level only) from Ribbon SBC eg: Calls failed, Calls Succeeded, Call Currently Up, etc.
	
	.EXAMPLE
	get-uxsystemcallstats
    
    .EXAMPLE
    $Creds = Get-credential
	$Obj = connect-uxgateway -uxhostname lyncsbc01.COMPANY.co.uk -Credentials $Creds
	get-uxsystemcallstats -uxSession $Obj

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
	invoke-uxbackup -backupdestination c:\backup -backupfilename lyncgw01backup01
	
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
        [PSCustomObject]$uxSession,
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


    $args1 = $Arguments
    $url = "https://$uxHost/rest/$resource"
    if ($Details) {
        $url += "?details=true" 
    }
	
    Write-verbose "Connecting to $url"
	
    Try {
        $uxrawdata = Invoke-RestMethod -Uri $url -Method GET -WebSession $SessionVar -ErrorAction Stop
    }
	
    Catch {
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity)."
    }

    $Result = ([xml]$uxrawdata.trim()).root
    $Success = $Result.status.http_code
		
    #Check if connection was successful.HTTP code 200 is returned
    If ( $Success -ne "200") {
        #Unable to Login
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
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
	((get-uxresource -resource sipservertable).sipservertable_list).sipservertable_pk
	
	Create new SIP server table and specify a free resource ID (15 here)
	new-uxresource -args "Description=LyncMedServers" -resource sipservertable/15
	
	.LINK
	To find all the resources which can be queried, please refer to https://support.sonus.net/display/UXAPIDOC
	
	#>
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$resource,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]$ReturnElement,

        [Parameter(Mandatory = $false, Position = 3)]
        [string]$Arguments,

        [Parameter(Mandatory = $true, Position = 4)]
        [Int]$Index,

        [Parameter(Mandatory = $false, Position = 5)]
        [pscredential]$Credentials

    )
    
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


 
    $url = "https://$uxHost/rest/$resource/$Index"
    Write-verbose "Connecting to $url"
    Write-verbose "Adding: $Arguments "
    

    $msg = "Adding A New Entry to $resource on the $uxhost Gateway with ID $Index"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        Try {
            $uxrawdata = Invoke-RestMethod -Uri $url -Method PUT -Body $Arguments -WebSession $sessionvar -ErrorAction Stop
        }
	
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
    
        $Result = ([xml]$uxrawdata.trim()).root
        $Success = $Result.status.http_code
		
        #Check if connection was successful.HTTP code 200 is returned
        If ( $Success -ne "200") {
            #Unable to Login
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }

    
        If ( $Success -eq "401") {
            #Existing Resource
            throw "Error creating the new entry, is there an existing record at $url? .The error message is $_"
        }


        #If 500 message is returned
        If ( $Success -eq "500") {
            Write-Verbose -Message $uxrawdata
            throw "Unable to create a new resource. Ensure you have entered a unique resource id.Verify this using `"get-uxresource`" cmdlet"
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

	
	
	.LINK
	To find all the resources which can be queried, please refer to https://support.sonus.net/display/UXAPIDOC
	
	#>
    
    [cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = "High")]
    Param(
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession,

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

    # The Command MUST be in lowercase so converting
    $url = "https://$uxHost/rest/system?action=$($command.ToLower())"
    Write-verbose "Connecting to $url"
    Write-verbose "Adding: $Arguments"
    

    $msg = "Running $Command on the $uxhost Gateway"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        Try {
            $options = @{
                uri         = $url
                Method      = "POST"
                Body        = $Arguments
                WebSession  = $SessionVar
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
        
        
        If ( $Success -eq "401") {
            #Existing Resource
            throw "Error running Command .The error message is $_"
        }


        #If 500 message is returned
        If ( $Success -eq "500") {
            Write-Verbose -Message $uxrawdata
            throw "Error running Command .The error message is $_"
        }

        #Check if connection was successful.HTTP code 200 is returned
        If ( $Success -ne "200") {
            #Unable to Login
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
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
        [PSCustomObject]$uxSession,

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
    
    if ($resource -contains "http://") {
        Throw "Resource is not properly formatted. Please only pass the resource you wish to remove not the whole address such as transformationtable then index of the entry"
    }

    #The URL  which will be passed to the UX
    $url = "https://$uxHost/rest/$resource"
    if ($index) { $url += "/$index" }
    Write-verbose "Removing $url"
    Write-verbose "With: $Arguments "
    

    $msg = "Deleting A New Entry to $resource on the $uxhost Gateway"
    if ($index) { $msg += "with ID $Index" }
    if ($PSCmdlet.ShouldProcess($($msg))) {
        Try {
            $uxrawdata = Invoke-RestMethod -Uri $url -Method DELETE -Body $Arguments -WebSession $sessionvar -ErrorAction Stop
        }
	
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
    
        $Result = ([xml]$uxrawdata.trim()).root
        $Success = $Result.status.http_code
		
        
       

    
        If ( $Success -eq "401") {
            #Existing Resource
            throw "Error creating the new entry, is there an existing record at $url? .The error message is $_"
        }


        #If 500 message is returned
        If ( $Success -eq "500") {
            Write-Verbose -Message $uxrawdata
            throw "Unable to create a new resource. Ensure you have entered a unique resource id.Verify this using `"get-uxresource`" cmdlet"
        }

        #Check if connection was successful.HTTP code 200 is returned
        If ( $Success -ne "200") {
            #Unable to Login
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
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
        [PSCustomObject]$uxSession,

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
	
    #The URL  which will be passed to the UX
    $url = "https://$uxhostname/rest/$resource/$index"
    Write-verbose "Editing $url"
    Write-verbose "With: $Arguments "
    

    $msg = "Deleting A New Entry to $resource on the $uxhost Gateway with ID $Index"
    if ($PSCmdlet.ShouldProcess($($msg))) {
        Try {
            $uxrawdata = Invoke-RestMethod -Uri $url -Method POST -Body $Arguments -WebSession $sessionvar -ErrorAction Stop
        }
	
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
    
        $Result = ([xml]$uxrawdata.trim()).root
        $Success = $Result.status.http_code
		
    
        If ( $Success -eq "401") {
            #Existing Resource
            throw "Error creating the new entry, is there an existing record at $url? .The error message is $_"
        }


        #If 500 message is returned
        If ( $Success -eq "500") {
            Write-Verbose -Message $uxrawdata
            throw "Unable to create a new resource. Ensure you have entered a unique resource id.Verify this using `"get-uxresource`" cmdlet"
        }

        #Check if connection was successful.HTTP code 200 is returned
        If ( $Success -ne "200") {
            #Unable to Login
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
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
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession
        
    )
    Write-verbose "Called $($MyInvocation.MyCommand)"
    #$resource = Get-UxResourceName -functionname $MyInvocation.MyCommand
    
    $ResourceSplat = @{
        resource      = "transformationtable"
        ReturnElement = "transformationtable_list"
        Details       = $true
    }
    if ($uxSession) { $ResourceSplat.uxSession = $uxSession }


    #Further filtering of the object for this option - Here we want to see the whole details of the object.
    $Return = get-uxresource @ResourceSplat
    Write-Output $return.transformationtable
    
}

Function Get-UxTransformationEntry {
    <#
	.SYNOPSIS      
	 This cmdlet reports The Transformation from Ribbon SBC.
	 
	.DESCRIPTION
	 TBC
	
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

<##Function to get transformation table
Function get-uxtransformationtableOLD {
    <#
	.SYNOPSIS      
	 This cmdlet displays all the transformation table names and ID's
	
	.EXAMPLE
	 get-uxtransformationtable
	
	

    [cmdletbinding()]
    Param()

    if ($uxSession) {
        $uxSessionObj = $uxSession
        $uxhostname = $uxSession.host
        $SessionVar = $uxSession.Session
    }
    else {
        if ($DefaultSession) {
            $uxSessionObj = $DefaultSession
            $uxhostname = $DefaultSession.host
            $SessionVar = $DefaultSession.session
        }
        Else {
            Throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity)."
        }
    }

    $args1 = ""
    $url = "https://$uxhostname/rest/transformationtable"
	
    Try {
        $uxrawdata = Invoke-RestMethod -Uri $url -Method GET -WebSession $sessionvar -ErrorAction Stop
    }
	
    Catch {
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
    }
	
    #Check if connection was successful.HTTP code 200 is returned
    If ( $uxrawdata | select-string "<http_code>200</http_code>") {
	
        Write-Verbose $uxrawdata
		
        #Sanitise data and return as object
        Try {
            $m = $uxrawdata.IndexOf("<transformationtable_list")
            $length = ($uxrawdata.length - $m - 8)
            [xml]$uxdataxml = $uxrawdata.substring($m, $length)
        }
        Catch {
            throw "Unable to convert received data into XML correctly. The error message is $_"
        }
		
    }
    Else {
        #Unable to Login
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
    }
	
    #Create template object to hold the values of Tranformation tables
    $objTemplate = New-Object psobject
    $objTemplate | Add-Member -MemberType NoteProperty -Name id -Value $null
    $objTemplate | Add-Member -MemberType NoteProperty -Name Description -Value $null
	
    #Create an empty array which will contain the output
    $objResult = @()
		
    #This object contains all the Transformation table objects. Do a foreach to grab friendly names of the transformation tables
    foreach ($objtranstable in $uxdataxml.transformationtable_list.transformationtable_pk) {
        Try {
            $uxrawdata2 = Invoke-RestMethod -Uri $($objtranstable.href) -Method GET -WebSession $sessionvar -ErrorAction Stop
        }
	
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
        #Check if connection was successful.HTTP code 200 is returned
        If ( $uxrawdata2 | select-string "<http_code>200</http_code>") {
	
            Write-Verbose $uxrawdata2
		
            #Sanitise data and return as object
            Try {
                $m = $uxrawdata2.IndexOf("<transformationtable id=")
                $length = ($uxrawdata2.length - $m - 8)
                [xml]$uxdataxml2 = $uxrawdata2.substring($m, $length)
				
                #Create template object and stuff all the transformation tables into it
                $objTemp = $objTemplate | Select-Object *
                $objTemp.id = $uxdataxml2.transformationtable.id
                $objTemp.description = $uxdataxml2.transformationtable.description
                $objResult += $objTemp
            }
            Catch {
                throw "Unable to convert received data into XML correctly. The error message is $_"
            }
			
        }
        Else {
            #Unable to Login
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
    }
    #This object contains all the transformation tables with id to description mapping
    $objResult
}


#Function to get transformation table entries from a specified transformation table
Function global:get-uxtransformationentryOLD {
    <#
	.SYNOPSIS      
	 This cmdlet displays the transformation table entries of a specified transformation table.
	 
	.DESCRIPTION
	This cmdlet displays the transformation table entries if a transformation table id is specified. To extract the tranformation table id execute "get-uxtransformationtable" cmdlet
	The output of the cmdlet contains InputField/OutputFields which are displayed as integer. To map the numbers to friendly names refer: bit.ly/Iy7JQS
	
	.PARAMETER uxtransformationtableid
	Enter here the transformation table id of the transformation table.To extract the tranformation table id execute "get-uxtransformationtable" cmdlet
	
	.EXAMPLE
	 get-uxtransformationentry -uxtransformationtableid 4
	
	
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'To find the ID of the transformation table execute "get-uxtransformationtable" cmdlet')]
        [int]$uxtransformationtableid,
        #If using multiple servers you will need to pass the uxSession Object created by connect-uxGateway
        #Else it will look for the last created session using the command above
        [Parameter(Mandatory = $false, Position = 1)]
        [PSCustomObject]$uxSession
    )

    if ($uxSession) {
        $uxSessionObj = $uxSession
        $uxhostname = $uxSession.host
        $SessionVar = $uxSession.Session
    }
    else {
        if ($DefaultSession) {
            $uxSessionObj = $DefaultSession
            $uxhostname = $DefaultSession.host
            $SessionVar = $DefaultSession.session
        }
        Else {
            Throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity)."
        }
    }
    $args1 = ""
    #URL to grab the Transformation tables entry URL's when tranformation table ID is specified
    $url = "https://$uxhostname/rest/transformationtable/$uxtransformationtableid/transformationentry"
	
    Try {
        $uxrawdata = Invoke-RestMethod -Uri $url -Method GET -WebSession $sessionvar -ErrorAction Stop
    }
	
    Catch {
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
    }
	
    #Check if connection was successful.HTTP code 200 is returned
    If ( $uxrawdata | select-string "<http_code>200</http_code>") {
	
        Write-Verbose -Message $uxrawdata
		
        #Sanitise data and return as object
        Try {
            $m = $uxrawdata.IndexOf("<transformationentry_list")
            $length = ($uxrawdata.length - $m - 8)
            [xml]$uxdataxml = $uxrawdata.substring($m, $length)
        }
        Catch {
            throw "Unable to convert received data into XML correctly. The error message is $_"
        }
		
    }
    Else {
        #Unable to Login
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
    }
	
    #Grab the sequence of transformation entries in transformation.This information is stored in transformation table, so do have to query transformation table
    #FUNCTION get-uxresource IS USED IN THIS CMDLET
    Try {
        $transformationsequence = (((get-uxresource -resource "transformationtable/$uxtransformationtableid").transformationtable).sequence).split(",")
    }
	
    Catch {
        throw "Unable to find the sequence of transformation entries.The error is $_"
    }
	
    #Create template object to hold the values of Tranformation tables
    $objTemplate = New-Object psobject
    $objTemplate | Add-Member -MemberType NoteProperty -Name InputField -Value $null
    $objTemplate | Add-Member -MemberType NoteProperty -Name InputFieldValue -Value $null
    $objTemplate | Add-Member -MemberType NoteProperty -Name OutputField -Value $null
    $objTemplate | Add-Member -MemberType NoteProperty -Name OutputFieldValue -Value $null
    $objTemplate | Add-Member -MemberType NoteProperty -Name MatchType -Value $null
    $objTemplate | Add-Member -MemberType NoteProperty -Name Description -Value $null
    $objTemplate | Add-Member -MemberType NoteProperty -Name ID -Value $null
    $objTemplate | Add-Member -MemberType NoteProperty -Name SequenceID -Value $null
	
    #Create an empty array which will contain the output
    $objResult = @()
		
    #This object contains all the Transformation table objects. Do a foreach to grab friendly names of the transformation tables
    foreach ($objtransentry in $uxdataxml.transformationentry_list.transformationentry_pk) {
        Try {
            $uxrawdata2 = Invoke-RestMethod -Uri $($objtransentry.href) -Method GET -WebSession $sessionvar -ErrorAction Stop
        }
	
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
        #Check if connection was successful.HTTP code 200 is returned
        If ( $uxrawdata2 | select-string "<http_code>200</http_code>") {
	
            Write-Verbose $uxrawdata2
		
            #Sanitise data and return as object
            Try {
                $m = $uxrawdata2.IndexOf("<transformationentry id=")
                $length = ($uxrawdata2.length - $m - 8)
                [xml]$uxdataxml2 = $uxrawdata2.substring($m, $length)
				
                #Sanitise the transformation table entry as it also contains the transformation table id (eg: 3:1, we only need 1)
                $transformationtableentryidraw = $uxdataxml2.transformationentry.id
                $transformationtableentryidfor = $transformationtableentryidraw.Substring(($transformationtableentryidraw.IndexOf(":") + 1), $transformationtableentryidraw.Length - ($transformationtableentryidraw.IndexOf(":") + 1))
				
                #Create template object and stuff all the transformation tables into it
                $objTemp = $objTemplate | Select-Object *
                $objTemp.InputField = $uxdataxml2.transformationentry.InputField
                $objTemp.InputFieldValue = $uxdataxml2.transformationentry.InputFieldValue
                $objTemp.OutputField = $uxdataxml2.transformationentry.OutputField
                $objTemp.OutputFieldValue = $uxdataxml2.transformationentry.OutputFieldValue
                $objTemp.MatchType = $uxdataxml2.transformationentry.MatchType
                $objTemp.Description = $uxdataxml2.transformationentry.Description
                $objTemp.ID = $transformationtableentryidfor
                #Searches for the position in an array of a particular ID
                $objTemp.SequenceID = ($transformationsequence.IndexOf($objTemp.ID) + 1)
                $objResult += $objTemp
            }
            Catch {
                throw "Unable to convert received data into XML correctly. The error message is $_"
            }
			
        }
        Else {
            #Unable to Login
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
    }
    #This object contains all the transformation tables with id to description mapping
    $objResult
}
#>

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
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession,
        #Description of the new tablle
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateLength(1, 64)]
        [string]$Description
    )
        

    # First thing we need to do is get a new TableId
    try {
        if ($uxSession) {
            [int]$NewTransformationTableId = (get-uxtransformationtable -uxSession $uxSession | measure -Maximum).Maximum + 1 
        }
        else {
            [int]$NewTransformationTableId = (get-uxtransformationtable | measure -Maximum).Maximum + 1 
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
    Write-Output $return.transformationtable

}

<#
#Function to create new transformation table
Function global:new-uxtransformationtableOLD {
    <#
	.SYNOPSIS      
	 This cmdlet creates a new transformation table (not transformation table entry)
	 
	.DESCRIPTION
	This cmdlet creates a transformation table (not transformation table entry).
	
	.PARAMETER Description
	Enter here the Description (Name) of the Transformation table.This is what will be displayed in the Ribbon GUI
	
	.EXAMPLE
	 new-uxtransformationtable -Description "LyncToPBX"
	
	
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateLength(1, 64)]
        [string]$Description
    )
	
    #DEPENDENCY ON get-uxtransformationtable FUNCTION TO GET THE NEXT AVAILABLE TRANSFORMATIONTABLEID
    Try {
        $transformationtableid = ((get-uxtransformationtable | select -ExpandProperty id | Measure-Object -Maximum).Maximum) + 1
    }
    Catch {
        throw "Command failed when trying to execute the Transformationtableid using `"get-uxtransformationtable`" cmdlet.The error is $_"
    }
	
    #URL for the new transformation table
    $url = "https://$uxhostname/rest/transformationtable/$transformationtableid"
	
    Try {
        $uxrawdata = Invoke-RestMethod -Uri $url -Method PUT -Body "Description=$Description" -WebSession $sessionvar -ErrorAction Stop
    }
	
    Catch {
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
    }
    #If table is successfully created, 200OK is returned
    If ( $uxrawdata | select-string "<http_code>200</http_code>") {
	
        Write-Verbose -Message $uxrawdata
    }
    #If 500 message is returned
    ElseIf ($uxrawdata | select-string "<http_code>500</http_code>") {
        Write-Verbose -Message $uxrawdata
        throw "Unable to create transformation table. Ensure you have entered a unique transformation table id"
    }
    #If no 200 or 500 message
    Else {
        #Unable to Login
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
    }
	
    #Sanitise data and return as object for verbose only
    Try {
        $m = $uxrawdata.IndexOf("<transformationtable id=")
        $length = ($uxrawdata.length - $m - 8)
        [xml]$uxdataxml = $uxrawdata.substring($m, $length)
    }
    Catch {
        throw "Unable to convert received data into XML correctly. The error message is $_"
    }
    #Return Transformation table object just created
    write-verbose $uxdataxml.transformationtable
}

#>

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
            [int]$NewTransformationEntryId = (get-uxtransformationentry -uxTransformationTableId $TransformationTableId -uxSession $uxSession | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | measure -Maximum).Maximum + 1 
        }
        else {
            [int]$NewTransformationEntryId = (get-uxtransformationentry -uxTransformationTableId $TransformationTableId | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | measure -Maximum).Maximum + 1 
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
            [int]$sipservertableid = (get-uxsipservertable -uxSession $uxSession | Select -ExpandProperty id | measure -Maximum).Maximum + 1 
        }
        else {
            [int]$sipservertableid = (get-uxsipservertable | Select -ExpandProperty id | measure -Maximum).Maximum + 1 
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
    Write-Output $return.transformationtable

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
        [Parameter(Mandatory = $false, Position = 0)]
        [PSCustomObject]$uxSession,

        [Parameter(Mandatory = $true, Position = 1)]
        [int]$SipServerTableId,

        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Specifies the protocol to use for sending SIP messages")]
        [ValidateSet(0, 1)]
        [int]$ServerLookup = 0,
		
        [Parameter(Mandatory = $true, Position = 3, HelpMessage = "Specifies the priority of this server")]
        [ValidateRange(0, 16)]
        [int]$Priority,

        [Alias("ComputerName", "Server", "FQDN")]
        [Parameter(Mandatory = $true, Position = 4, HelpMessage = "Specifies the IP address or FQDN where this Signaling Group sends SIP messages")]
        [ValidateLength(1, 256)]
        [string]$Hostname,

        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "Specifies IPv4 addresses or IPv6 addresses")]
        [int]$HostIpVersion = 0,

        [Parameter(Mandatory = $false, Position = 6, HelpMessage = "Specifies the port number to send SIP messages")]
        [ValidateRange(1024, 65535)]
        [string]$Port = 5061,

        [Parameter(Mandatory = $false, Position = 7, HelpMessage = "Specifies the protocol to use for sending SIP messages")]
        [ValidateRange(0, 9)]
        [string]$Protocol = 2,
		
        [Parameter(Mandatory = $false, Position = 8, HelpMessage = "Specifies the TLS Profile ID")]
        [ValidateRange(0, 9)]
        [string]$TLSProfileid,
		
        [Parameter(Mandatory = $false, Position = 9, HelpMessage = "Specifies the method to monitor server. None(0), SIP Options(1)")]
        [ValidateSet(0, 1)]
        [int]$Monitor = 1,
        
        [Parameter(Mandatory = $False, Position = 10)]
        [ValidateSet(0, 1)]
        [int]$ReuseTimeout = 0,

        [Parameter(Mandatory = $false, Position = 19)]
        [ValidateSet(1, 4)]
        [string]$TransportSocket = 4

        <#		[Parameter(Mandatory=$false,Position=9)]
		[ValidateRange(0,2)]
		[int]$ServerType = 0,

		[Parameter(Mandatory=$false,Position=10)]
		[ValidateLenght(1,256)]
		[string]$DomainName,

		[Parameter(Mandatory=$false,Position=11)]
		[ValidateRange(0,65535)]
		[int]$Weight = 0
		
		Parameters to be added later if needed
		
		[Parameter(Mandatory=$false,Position=11)]
		[ValidateRange(30,300)]
		[string]$KeepAliveFrequency,
		
		[Parameter(Mandatory=$false,Position=12)]
		[ValidateRange(5,500)]
		[string]$RecoverFrequency,
		
		[Parameter(Mandatory=$false,Position=13)]
		[ValidateLength(1,256)]
		[string]$LocalUserName,
		
		[Parameter(Mandatory=$false,Position=14)]
		[ValidateLenght(1,256)]
		[string]$PeerUserName,
		
		[Parameter(Mandatory=$false,Position=15)]
		[ValidateRange(0,16)]
		[string]$RemoteAuthorizationTable,
		
		[Parameter(Mandatory=$false,Position=16)]
		[ValidateRange(0,16)]
		[string]$ContactRegistrantTable,
		
		[Parameter(Mandatory=$false,Position=17)]
		[ValidateSet(0,1)]
		[string]$SessionURIValidation,
		
		[Parameter(Mandatory=$false,Position=18)]
		[ValidateSet(0,1)]
		[string]$ReuseTransport,
		
		[Parameter(Mandatory=$false,Position=19)]
		[ValidateSet(1,4)]
		[string]$TransportSocket,
		
		[Parameter(Mandatory=$False,Position=20)]
		[ValidateSet(0,1)]
		[int]$ReuseTimeout
#>		
    )

    # First thing we need to do is get a new TableId
    try {
        if ($uxSession) {
            [int]$sipserverentryid = (get-uxsipservertableentry -uxSipServerTableId $SipServerTableId  -uxSession $uxSession | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | measure -Maximum).Maximum + 1 
        }
        else {
            [int]$sipserverentryid = (get-uxsipservertableentry -uxSipServerTableId $SipServerTableId | Select-Object -ExpandProperty id | ForEach-Object { $_.split(":")[1] } | measure -Maximum).Maximum + 1 
        }
    }
    catch {
        Throw "Unable to get a new entry id"
    }
    
    # Setting Default Variables
    $ServerType = 0
    $DomainName = ""
    $Weight = 0

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
            [int]$sipprofileid = (get-uxsipprofile -uxSession $uxSession | Select-Object -ExpandProperty id | measure -Maximum).Maximum + 1 
        }
        else {
            [int]$sipprofileid = (get-uxsipprofile | Select-Object -ExpandProperty id | measure -Maximum).Maximum + 1 
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
    $msg = "Adding A New Entry to sipprofile Table on the Gateway with ID $sipprofileid"
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
    
    if ($sipprofileid) {
        $ResourceSplat = @{
            resource = "sipsg/$sipprofileid"
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


    <#
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [int]$signalgroupid

    )

    # Check if sipserver table id was added as parameter
    if (-Not $signalgroupid) { 

	
        $url = "https://$uxhostname/rest/sipsg"
	
        Try {
            $uxrawdata = Invoke-RestMethod -Uri $url -Method GET -WebSession $sessionvar -ErrorAction Stop
        }
	
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
        #Check if connection was successful.HTTP code 200 is returned
        If ( $uxrawdata | select-string "<http_code>200</http_code>") {
	
            Write-Verbose $uxrawdata
		
            #Sanitise data and return as object
            Try {
                $m = $uxrawdata.IndexOf("<sipsg_list")
                $length = ($uxrawdata.length - $m - 8)
                [xml]$uxdataxml = $uxrawdata.substring($m, $length)
            }
            Catch {
                throw "Unable to convert received data into XML correctly. The error message is $_"
            }
		
        }
        Else {
            #Unable to Login
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
	
        #Create template object to hold the values of Tranformation tables
        $objTemplate = New-Object psobject
        $objTemplate | Add-Member -MemberType NoteProperty -Name id -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Description -Value $null
	
        #Create an empty array which will contain the output
        $objResult = @()
		
        #This object contains all the sipprofile table objects. Do a foreach to grab friendly names of the sipprofile tables
        foreach ($objtranstable in $uxdataxml.sipsg_list.sipsg_pk) {
            Try {
                $uxrawdata2 = Invoke-RestMethod -Uri $($objtranstable.href) -Method GET -WebSession $sessionvar -ErrorAction Stop
            }
	
            Catch {
                throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
            }
	
            #Check if connection was successful.HTTP code 200 is returned
            If ( $uxrawdata2 | select-string "<http_code>200</http_code>") {
	
                Write-Verbose $uxrawdata2
		
                #Sanitise data and return as object
                Try {
                    $m = $uxrawdata2.IndexOf("<sipsg id=")
                    $length = ($uxrawdata2.length - $m - 8)
                    [xml]$uxdataxml2 = $uxrawdata2.substring($m, $length)
				
                    #Create template object and stuff all the sipprofile tables into it
                    $objTemp = $objTemplate | Select-Object *
                    $objTemp.id = $uxdataxml2.sipsg.id
                    $objTemp.description = $uxdataxml2.sipsg.description
                    $objResult += $objTemp
                }
                Catch {
                    throw "Unable to convert received data into XML correctly. The error message is $_"
                }
			
            }
            Else {
                #Unable to Login
                throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
            }
	
        }
        #This object contains all the sipprofile tables with id to description mapping
        $objResult
    }

    Else { get-uxsignalgroupid $signalgroupid }
#>
}


<#
#OLD Function to get signalgroupid
Function global:get-uxsignalgroupid {
    <#
	.SYNOPSIS      
	 This cmdlet displays the specified signalgroup ID's
	
	.EXAMPLE
	 get-uxsignalgroupid
	


        [cmdletbinding()]
        Param(
            [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'To find the ID of the signalgroup "get-uxsignalgroup" cmdlet')]
            [int]$signalgroupid
        )
        $args1 = ""
        $url = "https://$uxhostname/rest/sipsg/$signalgroupid"
            
        Try {
            $uxrawdata = Invoke-RestMethod -Uri $url -Method GET -WebSession $sessionvar -ErrorAction Stop
        }
            
        Catch {
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
            
        #Check if connection was successful.HTTP code 200 is returned
        If ( $uxrawdata | select-string "<http_code>200</http_code>") {
            
            Write-Verbose $uxrawdata
                
            #Sanitise data and return as object
            Try {
                $m = $uxrawdata.IndexOf("<sipsg id=")
                $length = ($uxrawdata.length - $m - 8)
                [xml]$uxdataxml = $uxrawdata.substring($m, $length)
            }
            Catch {
                throw "Unable to convert received data into XML correctly. The error message is $_"
            }
                
        }
        Else {
            #Unable to Login
            throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
        }
            

        #Create template object to hold the values of Tranformation tables
        $objTemplate = New-Object psobject
        $objTemplate | Add-Member -MemberType NoteProperty -Name Description -Value $null	
        $objTemplate | Add-Member -MemberType NoteProperty -Name customAdminState -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ProfileID -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Channels -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ServerSelection -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ServerClusterId -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RelOnQckConnect -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RelOnQckConnectTimer -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RTPMode -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RTPProxyMode -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RTPDirectMode -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name VideoProxyMode -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name VideoDirectMode -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name MediaConfigID -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ToneTableID -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ActionSetTableID -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RouteTableID -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RingBack -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name HuntMethod -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Direction -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name PlayCongestionTone -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Early183 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name AllowRefreshSDP -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name OutboundProxy -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ProxyIpVersion -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name NoChannelAvailableId -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name TimerSanitySetup -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name TimTimerCallProceeding -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ChallengeRequest -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name NotifyCACProfile -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name NonceLifetime -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Monitor -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name AuthorizationRealm -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ProxyAuthorizationTableID -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RegistrarID -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RegistrarTTL -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name OutboundRegistrarTTL -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name DSCP -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ListenPort_1 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Protocol_1 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name TLSProfileID_1 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name LocalIP_1 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ListenPort_2 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Protocol_2 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name TLSProfileID_2 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name LocalIP_2 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ListenPort_3 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Protocol_3 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name TLSProfileID_3 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name LocalIP_3 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ListenPort_4 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Protocol_4 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name TLSProfileID_4 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name LocalIP_4 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ListenPort_5 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Protocol_5 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name TLSProfileID_5 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name LocalIP_5 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ListenPort_6 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Protocol_6 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name TLSProfileID_6 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name LocalIP_6 -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name SIPtoQ850_TableID -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Q850toSIP_TableID -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name NetInterfaceSignaling -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name NATTraversalType -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name NATPublicIPAddress -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name PassthruPeerSIPRespCode -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name SGLevelMOHService -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name IngressSPRMessageTableList -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name EgressSPRMessageTableList -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name QoEReporting -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name VoiceQualityReporting -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RegisterKeepAlive -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name InteropMode -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name AgentType -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RegistrantTTL -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ADAttribute -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ADUpdateFrequency -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ADFirstUpdateTime -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name Office365FQDN -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name ICESupport -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name InboundNATTraversalDetection -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name InboundNATQualifiedPrefixesTableID -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name InboundSecureNATMediaLatching -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name InboundSecureNATMediaPrefix -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name InboundNATPeerRegistrarMaxEnabled -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name InboundNATPeerRegistrarMaxTTL -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RemoteHosts -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name RemoteMasks -Value $null
        $objTemplate | Add-Member -MemberType NoteProperty -Name SIPReSync -Value $null

            
        #Create an empty array which will contain the output
        $objResult = @()

                
        #Create template object and stuff all the sipprofile values into it
        $objTemp = $objTemplate | Select-Object *
        $objTemp.description = $uxdataxml.sipsg.description
        $objTemp.customAdminState = $uxdataxml.sipsg.customAdminState
        $objTemp.ProfileID = $uxdataxml.sipsg.profileid
        $objTemp.Channels = $uxdataxml.sipsg.Channels
        $objTemp.ServerSelection = $uxdataxml.sipsg.ServerSelection
        $objTemp.ServerClusterId = $uxdataxml.sipsg.ServerClusterId
        $objTemp.RelOnQckConnect = $uxdataxml.sipsg.RelOnQckConnect
        $objTemp.RelOnQckConnectTimer = $uxdataxml.sipsg.RelOnQckConnectTimer
        $objTemp.RTPMode = $uxdataxml.sipsg.RTPMode
        $objTemp.RTPProxyMode = $uxdataxml.sipsg.RTPProxyMode
        $objTemp.RTPDirectMode = $uxdataxml.sipsg.RTPDirectMode
        $objTemp.VideoProxyMode = $uxdataxml.sipsg.VideoProxyMode
        $objTemp.VideoDirectMode = $uxdataxml.sipsg.VideoDirectMode
        $objTemp.MediaConfigID = $uxdataxml.sipsg.MediaConfigID
        $objTemp.ToneTableID = $uxdataxml.sipsg.ToneTableID
        $objTemp.ActionSetTableID = $uxdataxml.sipsg.ActionSetTableID
        $objTemp.RouteTableID = $uxdataxml.sipsg.RouteTableID
        $objTemp.RingBack = $uxdataxml.sipsg.RingBack
        $objTemp.HuntMethod = $uxdataxml.sipsg.HuntMethod
        $objTemp.Direction = $uxdataxml.sipsg.Direction
        $objTemp.PlayCongestionTone = $uxdataxml.sipsg.PlayCongestionTone
        $objTemp.Early183 = $uxdataxml.sipsg.Early183
        $objTemp.AllowRefreshSDP = $uxdataxml.sipsg.AllowRefreshSDP
        $objTemp.OutboundProxy = $uxdataxml.sipsg.OutboundProxy
        $objTemp.ProxyIpVersion = $uxdataxml.sipsg.ProxyIpVersion
        $objTemp.ProxyIpVersion = $uxdataxml.sipsg.ProxyIpVersion
        $objTemp.NoChannelAvailableId = $uxdataxml.sipsg.NoChannelAvailableId
        $objTemp.TimerSanitySetup = $uxdataxml.sipsg.TimerSanitySetup
        $objTemp.TimTimerCallProceeding = $uxdataxml.sipsg.TimTimerCallProceeding
        $objTemp.ChallengeRequest = $uxdataxml.sipsg.ChallengeRequest
        $objTemp.NotifyCACProfile = $uxdataxml.sipsg.NotifyCACProfile
        $objTemp.NonceLifetime = $uxdataxml.sipsg.NonceLifetime
        $objTemp.Monitor = $uxdataxml.sipsg.Monitor
        $objTemp.AuthorizationRealm = $uxdataxml.sipsg.AuthorizationRealm
        $objTemp.ProxyAuthorizationTableID = $uxdataxml.sipsg.ProxyAuthorizationTableID
        $objTemp.RegistrarID = $uxdataxml.sipsg.RegistrarID
        $objTemp.RegistrarTTL = $uxdataxml.sipsg.RegistrarTTL
        $objTemp.OutboundRegistrarTTL = $uxdataxml.sipsg.OutboundRegistrarTTL
        $objTemp.DSCP = $uxdataxml.sipsg.DSCP
        $objTemp.ListenPort_1 = $uxdataxml.sipsg.ListenPort_1
        $objTemp.Protocol_1 = $uxdataxml.sipsg.Protocol_1
        $objTemp.TLSProfileID_1 = $uxdataxml.sipsg.TLSProfileID_1
        $objTemp.LocalIP_1 = $uxdataxml.sipsg.LocalIP_1
        $objTemp.ListenPort_2 = $uxdataxml.sipsg.ListenPort_2
        $objTemp.Protocol_2 = $uxdataxml.sipsg.Protocol_2
        $objTemp.TLSProfileID_2 = $uxdataxml.sipsg.TLSProfileID_2
        $objTemp.LocalIP_2 = $uxdataxml.sipsg.LocalIP_2
        $objTemp.ListenPort_3 = $uxdataxml.sipsg.ListenPort_3
        $objTemp.Protocol_3 = $uxdataxml.sipsg.Protocol_3
        $objTemp.TLSProfileID_3 = $uxdataxml.sipsg.TLSProfileID_3
        $objTemp.Protocol_3 = $uxdataxml.sipsg.Protocol_3
        $objTemp.LocalIP_3 = $uxdataxml.sipsg.LocalIP_3
        $objTemp.ListenPort_4 = $uxdataxml.sipsg.ListenPort_4
        $objTemp.Protocol_4 = $uxdataxml.sipsg.Protocol_4
        $objTemp.TLSProfileID_4 = $uxdataxml.sipsg.TLSProfileID_4
        $objTemp.LocalIP_4 = $uxdataxml.sipsg.LocalIP_4
        $objTemp.ListenPort_5 = $uxdataxml.sipsg.ListenPort_5
        $objTemp.Protocol_5 = $uxdataxml.sipsg.Protocol_5
        $objTemp.TLSProfileID_5 = $uxdataxml.sipsg.TLSProfileID_5
        $objTemp.LocalIP_5 = $uxdataxml.sipsg.LocalIP_5
        $objTemp.ListenPort_6 = $uxdataxml.sipsg.ListenPort_6
        $objTemp.Protocol_6 = $uxdataxml.sipsg.Protocol_6
        $objTemp.TLSProfileID_6 = $uxdataxml.sipsg.TLSProfileID_6
        $objTemp.LocalIP_6 = $uxdataxml.sipsg.LocalIP_6
        $objTemp.SIPtoQ850_TableID = $uxdataxml.sipsg.SIPtoQ850_TableID
        $objTemp.Q850toSIP_TableID = $uxdataxml.sipsg.Q850toSIP_TableID
        $objTemp.NetInterfaceSignaling = $uxdataxml.sipsg.NetInterfaceSignaling
        $objTemp.NATTraversalType = $uxdataxml.sipsg.NATTraversalType
        $objTemp.NATPublicIPAddress = $uxdataxml.sipsg.NATPublicIPAddress
        $objTemp.PassthruPeerSIPRespCode = $uxdataxml.sipsg.PassthruPeerSIPRespCode
        $objTemp.SGLevelMOHService = $uxdataxml.sipsg.SGLevelMOHService
        $objTemp.IngressSPRMessageTableList = $uxdataxml.sipsg.IngressSPRMessageTableList
        $objTemp.EgressSPRMessageTableList = $uxdataxml.sipsg.EgressSPRMessageTableList
        $objTemp.QoEReporting = $uxdataxml.sipsg.QoEReporting
        $objTemp.VoiceQualityReporting = $uxdataxml.sipsg.VoiceQualityReporting
        $objTemp.RegisterKeepAlive = $uxdataxml.sipsg.RegisterKeepAlive
        $objTemp.InteropMode = $uxdataxml.sipsg.InteropMode
        $objTemp.AgentType = $uxdataxml.sipsg.AgentType
        $objTemp.RegistrantTTL = $uxdataxml.sipsg.RegistrantTTL
        $objTemp.ADAttribute = $uxdataxml.sipsg.ADAttribute
        $objTemp.ADUpdateFrequency = $uxdataxml.sipsg.ADUpdateFrequency
        $objTemp.ADFirstUpdateTime = $uxdataxml.sipsg.ADFirstUpdateTime
        $objTemp.Office365FQDN = $uxdataxml.sipsg.Office365FQDN
        $objTemp.ICESupport = $uxdataxml.sipsg.ICESupport
        $objTemp.InboundNATTraversalDetection = $uxdataxml.sipsg.InboundNATTraversalDetection
        $objTemp.InboundNATQualifiedPrefixesTableID = $uxdataxml.sipsg.InboundNATQualifiedPrefixesTableID
        $objTemp.InboundSecureNATMediaLatching = $uxdataxml.sipsg.InboundSecureNATMediaLatching
        $objTemp.InboundSecureNATMediaPrefix = $uxdataxml.sipsg.InboundSecureNATMediaPrefix
        $objTemp.InboundNATPeerRegistrarMaxEnabled = $uxdataxml.sipsg.InboundNATPeerRegistrarMaxEnabled
        $objTemp.InboundNATPeerRegistrarMaxTTL = $uxdataxml.sipsg.InboundNATPeerRegistrarMaxTTL
        $objTemp.RemoteHosts = $uxdataxml.sipsg.RemoteHosts
        $objTemp.RemoteMasks = $uxdataxml.sipsg.RemoteMasks
        $objTemp.SIPReSync = $uxdataxml.sipsg.SIPReSync


        $objResult = $objTemp
                
        #This object contains all the signalgroup table objects. Do a foreach to grab friendly names of the sipprofile tables
        $objResult

}
#>

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
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'Short description/name of the SG')]
        [ValidateLength(1, 64)]
        [string]$Description ,

        [Parameter(Mandatory = $true, Position = 1, HelpMessage = 'Enable or Disable this signaling group')]
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
            [int]$newSipSigid = (get-uxsignalgroup -uxSession $uxSession | Select-Object -ExpandProperty id | measure -Maximum).Maximum + 1 
        }
        else {
            [int]$newSipSigid = (get-uxsignalgroup | Select-Object -ExpandProperty id | measure -Maximum).Maximum + 1 
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

    <#        

	
    #DEPENDENCY ON get-uxsipservertable FUNCTION TO GET THE NEXT AVAILABLE signalgroup ID
    Try {
        $sipsgid = ((get-uxsignalgroup | select -ExpandProperty id | Measure-Object -Maximum).Maximum) + 1
    }
    Catch {
        throw "Command failed when trying to execute the sipprofileid using `"get-uxsipprofile`" cmdlet.The error is $_"
    }
    $sipsgid
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




    #URL for the new signal group
    $args = "description=$description&customadminstate=$customadminstate&profileid=$ProfileID&ServerClusterId=$ServerClusterId&channels=$channels&mediaconfigid=$mediaconfigid&routetableid=$routetableid&ListenPort_1=$ListenPort_1&Protocol_1=$Protocol_1&TLSProfileID_1=$TLSProfileID_1&netinterfacesignaling=$netinterfacesignaling&remotehosts=$remotehosts&remotemasks=$remotemasks&relonqckconnect=$relonqckconnect&rtpmode=$rtpmode&rtpproxymode=$rtpproxymode&rtpdirectmode=$rtpdirectmode&videoproxymode=$videoproxymode&videodirectmode=$videodirectmode&huntmethod=$huntmethod&proxyipversion=$proxyipversion&dscp=$dscp&nattraversaltype=$nattraversaltype&icesupport=$icesupport&inboundnattraversaldetection=$inboundnattraversaldetection&icemode=$icemode"
    $url = "https://$uxhostname/rest/sipsg/$sipsgid"
	
    Try {
        $uxrawdata = Invoke-RestMethod -Uri $url -Method PUT -Body $args -WebSession $sessionvar -ErrorAction Stop
    }
	
    Catch {
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
    }
    #If table is successfully created, 200OK is returned
    If ( $uxrawdata | select-string "<http_code>200</http_code>") {
	
        Write-Verbose -Message $uxrawdata
    }
    #If 500 message is returned
    ElseIf ($uxrawdata | select-string "<http_code>500</http_code>") {
        Write-Verbose -Message $uxrawdata
        throw "Unable to create signalgroup. Ensure you have entered a unique signalgroup id"
    }
    #If no 200 or 500 message
    Else {
        #Unable to Login
        throw "Unable to process this command.Ensure you have connected to the gateway using `"connect-uxgateway`" cmdlet or if you were already connected your session may have timed out (10 minutes of no activity).The error message is $_"
    }
	
    #Sanitise data and return as object for verbose only
    Try {
        $m = $uxrawdata.IndexOf("<sipsg id=")
        $length = ($uxrawdata.length - $m - 8)
        [xml]$uxdataxml = $uxrawdata.substring($m, $length)
    }
    Catch {
        throw "Unable to convert received data into XML correctly. The error message is $_"
    }
    #Return sipserver table object just created
    write-verbose $uxdataxml.sipsg

#>
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
        [PSCustomObject]$uxSession
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

    $Status = Send-UxCommand -uxSession $uxSessionObj -Command reboot -ReturnElement status
    If ($status.http_code -eq "200") {
        Write-Host "Reboot initiated and completed succesfully" 
    }
}

