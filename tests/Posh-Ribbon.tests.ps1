[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateNotNullorEmpty()]
    [PSCredential]$Credential,
    [Parameter(Mandatory = $true, Position = 1)]
    [string]$uxhostname,
    [Parameter(Mandatory = $false, Position = 2)]
    [string]$2ndHostname,
    [Parameter(Mandatory = $false, Position = 2)]
    [string]$SBCuserName,
    [Parameter(Mandatory = $false, Position = 2)]
    [string]$SBCPassword
)


if(-not $credential ){
    $secpasswd = ConvertTo-SecureString $SBCPassword -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ($SBCuserName, $secpasswd)
}

$ProjectRoot = Resolve-Path "$PSScriptRoot\.."
$ModuleRoot = Split-Path (Resolve-Path "$ProjectRoot\*.psd1")
$ModuleName = Split-Path $ModuleRoot -Leaf
$ModulePsd = (Resolve-Path "$ProjectRoot\$ModuleName.psd1").Path
$ModulePsm = (Resolve-Path "$ProjectRoot\$ModuleName.psm1").Path
#$DefaultsFile = Join-Path $ProjectRoot "Tests\$($ModuleName).Pester.Defaults.json"

$ModuleLoaded = Get-Module $ModuleName
If ($null -eq $ModuleLoaded) {
    Import-Module $ModulePSD -Force
}
ElseIf ($null -ne $ModuleLoaded -and $ModuleLoaded -ne $ModulePSM) {
    Remove-Module $ModuleName -Force -ErrorAction SilentlyContinue
    Import-Module $ModulePSD -Force
}

Describe "Connection" {
    $1stSession = connect-uxgateway -uxhostname $uxhostname -credentials $Credential
            
    Context "When Logging In with Actual Credentials" {
        it 'uxSession return object should include the host name provided above' {
            $1stSession.host | Should -be $uxhostname
        }
        it 'uxSession return object should include a websession' {
            $1stSession.session | Should -be $true
        }
        it 'uxSession return object should include a credential' {
            $1stSession.credentials | Should -be $true
        }
    }
    
    Context "When Logging In with wrong hostname " {
        it 'uxSession return object should throw an error' {
            { connect-uxgateway -uxhostname "kkk.no.local" -credentials $Credential -ea stop } | should throw
        }
      
    }
    Context "When Logging In with wrong credentials " {
        $secpasswd = ConvertTo-SecureString "PlainTextPassword" -AsPlainText -Force
        $mycreds = New-Object System.Management.Automation.PSCredential ("username", $secpasswd)

        it 'uxSession return object should throw an error' {
            { connect-uxgateway -uxhostname $uxhostname -Credentials $mycreds -ea stop } | should throw
        }
      
    }
    if ($2ndHostname) {
        $2ndSession = connect-uxgateway -uxhostname $2ndHostname -credentials $Credential
        Context "Testing Connections Using two Sessions" {
            
            it 'uxSession return object for first session should include the host name provided' {
                
                $1stSession.host | Should -be $uxhostname
            }
            it 'uxSession return object for first session should include the host name provided' {
                
                $2ndSession.host | Should -be $2ndHostname
            }            
                  
            it "The First Session host Should not match the second session" {
                $1stSession.host -eq $2ndSession.host | Should -Be $false
            }
        
        }
    }
}
Describe "Getting Information Back from Get Cmdlets" {
    $1stSession = connect-uxgateway -uxhostname $uxhostname -credentials $Credential -ea stop
    if ($2ndHostname) {
        $2ndSession = connect-uxgateway -uxhostname $2ndHostname -credentials $Credential
    }
    Context "Testing the `"Engine`" cmdlet get-UXResource " {
        it "should not error if we ask for a valid resource" {
            { Get-UxResource -resource system -ReturnElement system -ea stop } | Should -Not -Throw
        }
        it "should return a valid XML response when asking for a return element" {
            Get-UxResource -resource system -ReturnElement system -ea stop | Should -BeOfType System.Xml.XmlElement
        }
        it "should return a valid XML response when not asking for a return element" {
            Get-UxResource -resource system -ea stop | Should -BeOfType System.Xml.XmlElement
        }
        it "should return a valid XML response when not asking for a return element from a declared session" {
            Get-UxResource -uxSession $1stSession -resource system -ea stop | Should -BeOfType System.Xml.XmlElement
        }
        it "should return a valid XML response when not asking for a return element from a declared session" {
            Get-UxResource -uxSession $1stSession -resource system -ReturnElement system -ea stop | Should -BeOfType System.Xml.XmlElement
        }
        it "should throw if we ask for an invalid resource" {
            { Get-UxResource -uxSession $1stSession -resource zzzz -ea stop } | Should -Throw
        }
    }
    

    Context "Getting System Info testing get-uxSystemInfo" {
        connect-uxgateway -uxhostname $uxhostname -credentials $Credential -ea stop
        it 'An XML object Should be returned for the DEFAULT session' {
            
            (Get-UxSystemInfo) | Should -BeOfType System.Xml.XmlElement
        }
        
        it 'A string object Should be returned for vendor for the DEFAULT session' {
            
            (Get-UxSystemInfo).vendor | Should -beoftype String
        }
    
   
        $PrimarySBC = Get-UxSystemInfo -uxSession $1stSession 
        it 'An XML object Should be returned for a NAMED session' {
            
            $PrimarySBC | Should -BeOfType System.Xml.XmlElement
        }
        
        it 'A string object Should be returned for vendor for a NAMED session' {
            $PrimarySBC.vendor | Should -beoftype String
        }
    
        if ($2ndHostname) {
            
            $SecondSBC = Get-UxSystemInfo -uxSession $2ndSession 
            it 'The return object should not be the same as the primary connection' {
                
                $PrimarySBC.href -ne $SecondSBC.href | Should -be $true
            }
            
        
        }
    }

    Context "Getting System Info testing get-uxSystemCallStats" {
        connect-uxgateway -uxhostname $uxhostname -credentials $Credential -ea stop
        it 'An XML object Should be returned for the DEFAULT session' {
            
            (Get-UxSystemCallStats) | Should -BeOfType System.Xml.XmlElement
        }
        
        it 'A string object Should be returned for href for the DEFAULT session' {
            
            (Get-UxSystemCallStats).href | Should -beoftype String
        }
    
   
        $PrimarySBC = Get-UxSystemCallStats -uxSession $1stSession 
        it 'An XML object Should be returned for a NAMED session' {
            
            $PrimarySBC | Should -BeOfType System.Xml.XmlElement
        }
        
        it 'A string object Should be returned for href for a NAMED session' {
            $PrimarySBC.href | Should -beoftype String
        }
    
        if ($2ndHostname) {
            
            $SecondSBC = Get-UxSystemCallStats -uxSession $2ndSession 
            it 'The return object should not be the same as the primary connection' {
                
                $PrimarySBC.href -ne $SecondSBC.href | Should -be $true
            }
            
        
        }
    }

    Context "Getting System Info testing get-UxSystemLog" {
        connect-uxgateway -uxhostname $uxhostname -credentials $Credential -ea stop
        it 'An XML object Should be returned for the DEFAULT session' {
            
            (Get-UxSystemLog) | Should -BeOfType System.Xml.XmlElement
        }
        
        it 'A string object Should be returned for href for the DEFAULT session' {
            
            (Get-UxSystemLog).href | Should -beoftype String
        }
    
   
        $PrimarySBC = Get-UxSystemLog -uxSession $1stSession 
        it 'An XML object Should be returned for a NAMED session' {
            
            $PrimarySBC | Should -BeOfType System.Xml.XmlElement
        }
        
        it 'A string object Should be returned for href for a NAMED session' {
            $PrimarySBC.href | Should -beoftype String
        }
    
        if ($2ndHostname) {
            
            $SecondSBC = Get-UxSystemLog -uxSession $2ndSession 
            it 'The return object should not be the same as the primary connection' {
                
                $PrimarySBC.href -ne $SecondSBC.href | Should -be $true
            }
            
        
        }
    }

    Context "Getting System Info testing get-UxTransformationTable" {
        connect-uxgateway -uxhostname $uxhostname -credentials $Credential -ea stop
        it 'An XML object Should be returned for the DEFAULT session' {
            
            (Get-UxTransformationTable) | Should -BeOfType System.Xml.XmlElement
        }
        
        it 'A string object Should be returned for href element of the first object for the DEFAULT session' {
            
            (Get-UxTransformationTable)[0].href | Should -beoftype String
        }
    
   
        $PrimarySBC = Get-UxTransformationTable -uxSession $1stSession 
        it 'An XML object Should be returned for a NAMED session' {
            
            $PrimarySBC | Should -BeOfType System.Xml.XmlElement
        }
        
        it 'A string object Should be returned for href element of the first object for a NAMED session' {
            $PrimarySBC[0].href | Should -beoftype String
        }
    
        if ($2ndHostname) {
            
            $SecondSBC = Get-UxTransformationTable -uxSession $2ndSession 
            it 'The return object should not be the same as the primary connection' {
                
                $PrimarySBC[0].href -ne $SecondSBC[0].href | Should -be $true
            }
            
        
        }
    }
    Context "Testing get-UxTransformationTable and getting detailed entries for the first table" {
        connect-uxgateway -uxhostname $uxhostname -credentials $Credential -ea stop
        $1stTable = (Get-UxTransformationTable)[0].id
        if (-not $1stTable) {
            $1stTable = (Get-UxTransformationTable)[1].id
        }
        it 'An XML object Should be returned for the DEFAULT session' {
            
            (Get-UxTransformationTable $1stTable) | Should -BeOfType System.Xml.XmlElement
        }
        
     
    
   
        $PrimarySBC = Get-UxTransformationTable $1stTable -uxSession $1stSession 
        it 'An XML object Should be returned for a NAMED session' {
            
            $PrimarySBC | Should -BeOfType System.Xml.XmlElement
        }
        
    
    
        if ($2ndHostname) {
            $1stTable = (Get-UxTransformationTable -uxSession $2ndSession)[0].id
            if (-not $1stTable) {
                $1stTable = (Get-UxTransformationTable -uxSession $2ndSession)[1].id
            }
            $SecondSBC = Get-UxTransformationTable -uxSession $2ndSession 
            $1stTable = $SecondSBC[0].id
            if ($null -eq $1stTable) {
                $1stTable = $SecondSBC[1].id
            }
            it 'The return object should not be the same as the primary connection' {
                
                $PrimarySBC[0].href -ne $SecondSBC[0].href | Should -be $true
            }
            
        
        }
    }




}
Describe "Creating New Sip Server Tables and Entires" {
    
    # Lets setup some variables that we can use to keep track of the new entries.
    $testTableName1 = -join ((65..90) + (97..122) | Get-Random -Count 5 | % { [char]$_ })
    $testTableName2 = -join ((65..90) + (97..122) | Get-Random -Count 5 | % { [char]$_ })
    $testTableName3 = -join ((65..90) + (97..122) | Get-Random -Count 5 | % { [char]$_ })
    $TableDescription1 = "[!PSTR#] Test For {0}" -f $testTableName1
    $TableDescription2 = "[!PSTR#] Test For {0}" -f $testTableName2
    $TableDescription3 = "[!PSTR#] Test For {0}" -f $testTableName3
    $idTracker = 0

    Context "Creating A New SIP Server Table `'New-UXSipServerTable`' and it's Entries" {
       
        
        it "Should Not Throw an Error when creating & Deleting a table" {
            # We create this indivdual object just for testing for errors
            { 
                $return = New-UxSipServerTable -Description $TableDescription1 -confirm:$false -ea stop
                Remove-UxResource -resource "sipservertable/$($return.id)" -confirm:$false -ea stop
                
            } | Should -Not -Throw

        }
        
        

        $returnObj = New-UxSipServerTable -Description $TableDescription2 -confirm:$false

        it "Should return a table with the same description" {
            $ReturnObj.Description -eq $TableDescription2 | Should -Be $true
        }

        it "Should return a table with an ID." {
            $ReturnObj.id | Should -not -Be $null
        }

        # Cleaning UP
        it "Should delete a table with an ID." {
            { Remove-UxResource -resource "sipservertable/$($ReturnObj.id)" -confirm:$false -ea stop } | Should -not -Throw
        }
        
        

    }
    
    Context "Creating an Entry in A Generated Table" {
        # Lets Create a blank table to add Entries to.
        $returnObj = New-UxSipServerTable -Description $TableDescription3 -confirm:$false
        # Lets Set Some Common Parameters
        $ParamsToSend = @{
            ServerLookup                     = 0
            ServerType                       = 0
            Weight                           = 0
            Host                             = "192.168.1.100"
            HostIpVersion                    = 0
            DomainName                       = "Domain.com"
            ServiceName                      = "sip"
            Port                             = 5060
            TransportSocket                  = 4
            ReuseTransport                   = 1
            ReuseTimeout                     = 0
            Protocol                         = 2
            Monitor                          = 1
            KeepAliveFrequency               = 30
            RecoverFrequency                 = 5
            LocalUserName                    = 'Anonymous'
            PeerUserName                     = 'Anonymous'
            Priority                         = 0
            RemoteAuthorizationTableID       = 0
            ContactRegistrantTableID         = 0
            StaggerRegistration              = 0
            ClearRemoteRegistrationOnStartup = 0
            SessionURIValidation             = 0
            ContactURIRandomizer             = 0
            RetryNonStaleNonce               = 1
            TLSProfileID                     = 0
            AuthorizationOnRefresh           = 1
        }
    
        It "Should create a new entry in the the new table" {
            { New-UxSipServerEntry @ParamsToSend -SipServerTableId $ReturnObj.id -confirm:$false -ea stop } | Should -Not -Throw
        } 

        # Cleaning UP
        it "Should delete a entry with an ID of 1 in the Dynamically created table." {
            # We are deleting the first one as there should only ever be on in this dynamic entry
            { Remove-UxResource -resource "sipservertable/$($ReturnObj.id)/sipserver/1" -confirm:$false -ea stop } | Should -not -Throw
        }

        # Cleaning UP table
        it "Should delete a table after the entry has been deleted." {
            { Remove-UxResource -resource "sipservertable/$($ReturnObj.id)" -confirm:$false -ea stop } | Should -not -Throw
        }
    }

}