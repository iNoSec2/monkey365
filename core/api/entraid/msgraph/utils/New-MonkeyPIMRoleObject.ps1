# Monkey365 - the PowerShell Cloud Security Tool for Azure and Microsoft 365 (copyright 2022) by Juan Garrido
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Function New-MonkeyPIMRoleObject {
<#
        .SYNOPSIS
		Create a new PIM role object

        .DESCRIPTION
		Create a new PIM role object

        .INPUTS

        .OUTPUTS

        .EXAMPLE

        .NOTES
	        Author		: Juan Garrido
            Twitter		: @tr1ana
            File Name	: New-MonkeyPIMRoleObject
            Version     : 1.0

        .LINK
            https://github.com/silverhack/monkey365
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Scope="Function")]
	[CmdletBinding()]
	Param (
        [parameter(Mandatory= $True, ValueFromPipeline = $True, HelpMessage="PIM role object")]
        [Object]$InputObject
    )
    Process{
        try{
            #Create ordered dictionary
            $PIMObject = [ordered]@{
                id = $InputObject.Id;
                templateId = $InputObject.Id;
		        name = $InputObject.displayName;
                displayName = $InputObject.displayName;
                description = $InputObject.description;
                deletedDateTime = $InputObject.deletedDateTime;
                policy = $null;
                roleInUse = $false;
                activeAssignment = [PsCustomObject]@{
                    users = $null;
                    groups = $null;
                    servicePrincipals = $null;
                    isUsed = $false;
                    duplicateUsers = $null;
                    totalActiveMembers = $null;
                }
                eligibleAssignment = [PsCustomObject]@{
                    users = $null;
                    groups = $null;
                    servicePrincipals = $null;
                    isUsed = $false;
                    duplicateUsers = $null;
                    totalEligibleMembers = $null;
                }
                totalMembers = $null;
            }
            #Create PsObject
            $_obj = New-Object -TypeName PsObject -Property $PIMObject
            #return object
            return $_obj
        }
        catch{
            $msg = @{
			    MessageData = ($message.MonkeyObjectCreationFailed -f "PIM role object");
			    callStack = (Get-PSCallStack | Select-Object -First 1);
			    logLevel = 'error';
			    InformationAction = $O365Object.InformationAction;
			    Tags = @('PIMObjectError');
		    }
		    Write-Error @msg
            $msg.MessageData = $_
            $msg.LogLevel = "Verbose"
            $msg.Tags+= "PIMObjectError"
            [void]$msg.Add('verbose',$O365Object.verbose)
		    Write-Verbose @msg
        }
    }
}
