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


Function Get-MonkeyMSGraphGroupTransitiveMember{
    <#
        .SYNOPSIS
		Get transitive group membership for a group

        .DESCRIPTION
		Get transitive group membership for a group

        .INPUTS

        .OUTPUTS

        .EXAMPLE

        .NOTES
	        Author		: Juan Garrido
            Twitter		: @tr1ana
            File Name	: Get-MonkeyMSGraphGroupTransitiveMember
            Version     : 1.0

        .LINK
            https://github.com/silverhack/monkey365
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true, ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [string]$GroupId,

        [parameter(Mandatory=$true, HelpMessage="Parent groups of group")]
        [Array]$Parents,

        [parameter(Mandatory = $false)]
        [ValidateSet("v1.0","beta")]
        [String]$APIVersion = "v1.0"
    )
    Begin{
        $Environment = $O365Object.Environment
        #Get Graph Auth
        $graphAuth = $O365Object.auth_tokens.MSGraph
    }
    Process{
        $msg = @{
            MessageData = ($message.GroupMembersMessage -f $GroupId);
            callStack = (Get-PSCallStack | Select-Object -First 1);
            logLevel = 'verbose';
            InformationAction = $O365Object.InformationAction;
            Verbose = $O365Object.verbose;
            Tags = @('AzureGraphGroupMembers');
        }
        Write-Verbose @msg
        #Get members
        $objectType = ('groups/{0}/transitiveMembers' -f $GroupId)
        $params = @{
            Authentication = $graphAuth;
            ObjectType = $objectType;
            Environment = $Environment;
            ContentType = 'application/json';
            Method = "GET";
            APIVersion = $APIVersion;
            InformationAction = $O365Object.InformationAction;
            Verbose = $O365Object.verbose;
            Debug = $O365Object.debug;
        }
        $group_members = Get-MonkeyMSGraphObject @params
        if($group_members){
            foreach($member in $group_members){
                If($member.'@odata.type' -eq "#microsoft.graph.group"){
                    if($member.id -notin $Parents){
                        $Parents +=$member.id
                        $p = @{
                            groupId = $member.id
                            Parents = $Parents
                            InformationAction = $O365Object.InformationAction;
                            Verbose = $O365Object.verbose;
                            Debug = $O365Object.debug;
                        }
                        Get-MonkeyMSGraphGroupTransitiveMember @p
                    }
                    Else{
                        $msg = @{
                            MessageData = ($message.PotentialNestedGroupMessage -f $member.displayName, $GroupId);
                            callStack = (Get-PSCallStack | Select-Object -First 1);
                            logLevel = 'verbose';
                            InformationAction = $O365Object.InformationAction;
                            Verbose = $O365Object.verbose;
                            Tags = @('AzureGraphGroupMembers');
                        }
                        Write-Verbose @msg
                    }
                }
                Else{
                    $member
                }
            }
        }
    }
}

