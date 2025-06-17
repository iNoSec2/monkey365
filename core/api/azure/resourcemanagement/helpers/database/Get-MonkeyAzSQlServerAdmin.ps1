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

Function Get-MonkeyAzSQlServerAdmin {
    <#
        .SYNOPSIS
		Get sql server administrator from Azure

        .DESCRIPTION
		Get sql server administrator from Azure

        .INPUTS

        .OUTPUTS

        .EXAMPLE

        .NOTES
	        Author		: Juan Garrido
            Twitter		: @tr1ana
            File Name	: Get-MonkeyAzSQlServerAdmin
            Version     : 1.0

        .LINK
            https://github.com/silverhack/monkey365
    #>

	[CmdletBinding()]
	Param (
        [Parameter(Mandatory=$True, ValueFromPipeline = $True)]
        [Object]$Server,

        [Parameter(Mandatory=$false, ValueFromPipeline = $True)]
        [Switch]$PostgreSQL,

        [parameter(Mandatory=$false, HelpMessage="API version")]
        [String]$APIVersion = "2019-06-01-preview"
    )
    Process{
        try{
            if($PostgreSQL.IsPresent){
                $p = @{
                    Id = ($Server.Id).Substring(1);
                    Resource = "administrators";
                    ApiVersion = $APIVersion;
                    Verbose = $O365Object.verbose;
                    Debug = $O365Object.debug;
                    InformationAction = $O365Object.InformationAction;
                }
                Get-MonkeyAzObjectById @p
            }
            else{
                $p = @{
                    Id = ($Server.Id).Substring(1);
                    Resource = "administrators/activeDirectory";
                    ApiVersion = $APIVersion;
                    Verbose = $O365Object.verbose;
                    Debug = $O365Object.debug;
                    InformationAction = $O365Object.InformationAction;
                }
                Get-MonkeyAzObjectById @p
            }
        }
        catch{
            Write-Verbose $_
        }
    }
    End{
        #Nothing to do here
    }
}
