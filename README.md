[![Build Status](https://dev.azure.com/chris-burns/Posh-Ribbon/_apis/build/status/EgoManiac.Posh-Ribbon?branchName=master)](https://dev.azure.com/chris-burns/Posh-Ribbon/_build/latest?definitionId=1&branchName=master)

# Posh-Ribbon Powershell Module
Previously known as RibbonSBCEdge

This project is a Powershell module that allow to control Ribbon SBC Edge with REST API.

**This project is completely independent from Ribbon Communication. Ribbon is not responsible for any issue with this module. If you have issue with Ribbon product contact the Ribbon support.**



This is Version 2 of the Module which has been developed and rewrote from the ground up to better comply with
PowerShell Module Design and provide a more modular approach to the cmdlets. Extending the cmdlets is much
easier now as they rely on a single "engine" to do the heavy lifting.

Adding additional "Get Modules" SHOULD be relatively simple. Just take a look at the existing cmdlets.

New: Ribbon SBC In Azure.

Ribbon SBC have now provided a virtual machine that you can test these scripts upon. Indeed, the Author uses a Azure VM as
part of their DevOps Release Pipleine. For further information :-
https://support.sonus.net/display/UXDOC80/SBC+SWe+Lite+Trial+Offer+for+Microsoft+Azure


## Version History

Version 2 is a rewrite and a more modular design By Chris Burns from GCIcom. http://www.posh.dev

Version 1 ( Now considered Legacy Code ) was written by Vikas Jaswal. http://www.allthingsuc.co.uk/about-me/

	Version 2.1     26/04/19    -  Updated Ready For Powershell Gallery - Chris Burns
    Version 2.1     25/04/19    -  Updated with some more Get and New Commands especially Call Routing Table - Chris Burns
    Version 2.0     15/04/19    -  *NEW Version* - Rewrite for modern module design, better use of [XML] accelerator and details switch,
                                    a new custom uxSession Object to allow for access to multiple SBC's at once and a Custom XML -> PSObject Parser - Chris Burns

    Version 1.7     20/12/18    - Match Ribbon rebranding, Update link to Ribbon Docs - Adrien Plessis
    Version 1.6     04/10/18    - Added new-uxsipprofile cmdlet - Kjetil Lindløkken
    Version 1.5     03/10/18    - Added optional parameter to the get-uxsipprofile cmdlet to add id directly - Kjetil Lindløkken
    Version 1.4     03/10/18    - Added new-uxsipserverentry cmdlet - Kjetil Lindløkken
    Version 1.3     02/10/18    - Added get-uxsipprofile, Get-uxsipprofileid, get-uxsipservertableentry cmdlets - Kjetil Lindløkken
    Version 1.2     02/10/16    - Added get-uxsipservertable, new-uxsippservertable cmdlets - Kjetil Lindløkken
    Version 1.1     03/12/13    - Added new-ux*, restart-ux*, and get-uxresource cmdlets - Vikas Jaswal
    Version 1.0     30/11/13    - Module Created - Vikas Jaswal


## Key Features

- Built-in cmdlets to query Sonus SBC for transformation tables, transformation entries, systems information, etc.
- Built-in cmdlets to create transformation tables and transformation entries
- Built-in cmdlets for running any command against the SBC. (Backup/Reboot)
- Rewrite includes a Core Engine (Get-UxResource) to do the XML translation and return the object back to the initiating cmndlet.
- Using Advanced functions, any cmdlet which will change data on the SBC will now ask for confirmation (override with -confirm:$false)
- Extensibility – Query, create, modify and delete any UX resource even the one’s which don’t have cmdlets associated!
- Scalability - Improved with Version 2. Now you can create a [PScustomObject]uxSession and save it as a variable. You can now call cmdlets with a uxSession parameter 
- Scalability – Manage Sonus SBC’s at scale. Query, create, modify and delete resources with extraordinary efficiency. 1 or 100 SBC’s, it doesn’t matter!
- Simplicity – Extremely simple to use, logical cmdlet naming and in-depth built-in help.

## Pre-requisites

- Sonus SBC software should be R3.0 or higher
- PowerShell v4.0 or higher - Version 2 has now increased this to version 4 for better compatibility (3.0 may still work but needs testing)
- Ensure you have applied the base version 3.0 license which contains the license for REST
- Ensure you have created a username and password for REST. For more details check out: http://www.allthingsuc.co.uk/accessing-sonus-ux-with-rest-apis/

## Getting Started

1. Will be submitted to PowerShell Gallery and eventually can be installed with Install-Module Posh-Ribbon

#### DEV's

1. Download the RibbonEdgePsRest PowerShell module from the button "Clone or download"
2. Copy the module to your machine. Ideally you want to copy the module to one of the following locations as these are default locations where PowerShell looks for modules when import-module is executed.
    - C:\Users\YOURUSERNAME\Documents\WindowsPowerShell\Modules
    - C:\Windows\system32\WindowsPowerShell\v1.0\Modules
3. Open PowerShell and import the module:
    - If the module is in one of the above locations (where PowerShell searches), you can just execute import-module RibbonSBCEdge
    - If the module is not in the default location you can execute import-module C:\RibbonEdgePsRest\RibbonSBCEdge.psm1 (replacing the path where you have copied the module to)
4. To discover what cmdlets are available execute: get-command –module RibbonSBCEdge. Full PowerShell cmdlet help is available for all cmdlets.
5. For complete usage, see: http://www.allthingsuc.co.uk/powershell-module-for-sonus-sbc-10002000/

## Cmdlets Included

        'Connect-UxGateway',
        'Get-UxSystemInfo',
        'Get-UxSystemCallStats',
        'Get-UxSystemLog',
        'Get-UxCallRoutingTable',
        'Get-UxCallRoutingEntry',
        'New-UxCallRoutingTable',
        'New-UxCallRoutingEntry',
        'Invoke-UxBackup',
        'Get-UxResource',
        'Get-uxTableToParameter',
        'Get-UxReRouteTable',
        'New-UxResource',
        'Send-UxCommand',
        'Remove-UxResource',
        'Set-UxResource',
        'Get-UxTransformationTable',
        'Get-UxTransformationEntry',
        'New-UxTransformationTable',
        'New-UxTransformationEntry',
        'Get-UxSipServerTable',
        'Get-UxSipProfile',
        'Get-UxSipServerTableEntry',
        'New-UxSipProfile',
        'Get-UxSignalGroup',
        'New-UxSignalGroup',
        'New-UxSipServerTable',
        'New-UxSipServerEntry',
        'Copy-UxTransformationTables',
        'Restart-UxGateway'
