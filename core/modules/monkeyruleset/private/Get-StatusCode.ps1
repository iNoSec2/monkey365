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

function Get-StatusCode{
    <#
        .SYNOPSIS
        Return a status code from level value

        .DESCRIPTION
        Return a status code from level value

        .INPUTS

        .OUTPUTS

        .EXAMPLE

        .NOTES
	        Author		: Juan Garrido
            Twitter		: @tr1ana
            File Name	: Get-StatusCode
            Version     : 1.0

        .LINK
            https://github.com/silverhack/monkey365
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    Param (
        [parameter(Mandatory=$true, ValueFromPipeline = $True, HelpMessage="Level")]
        [AllowNull()]
        [AllowEmptyString()]
        [String]$InputObject
    )
    Process{
        try{
            If($null -eq $InputObject -or $InputObject -eq [System.String]::Empty){
                return "manual"
            }
            Elseif($InputObject.ToLower() -eq 'good'){
                return "pass"
            }
            else{
                return "fail"
            }
        }
        catch{
            Write-Error $_
        }
    }
}

