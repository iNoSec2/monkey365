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

Function Wait-MonkeyJob{
    <#
        .SYNOPSIS
            Waits until MonkeyJob(s) are finished
        .DESCRIPTION
            Waits until MonkeyJob(s) are finished
        .NOTES
	        Author		: Juan Garrido
            Twitter		: @tr1ana
            File Name	: Wait-MonkeyJob
            Version     : 1.0

        .LINK
            https://github.com/silverhack/monkey365
        .PARAMETER Job
            The job object to query for
        .PARAMETER Name
            The name of the jobs to query for
        .PARAMETER Id
            The Id of the jobs to query for
        .PARAMETER RunspacePoolId
            The runspacePool Id of the jobs to query for
        .PARAMETER State
            The State of the job that you want to display. Accepted values are:

            NotStarted
            Running
            Completed
            Failed
            Stopped
            Blocked
            Suspended
            Disconnected
            Suspending
            Stopping
            AtBreakpoint
    #>
    [cmdletbinding(DefaultParameterSetName='All')]
    Param
    (
        [Parameter(Mandatory=$true, ParameterSetName='Job', position=0, ValueFromPipeline=$true, HelpMessage="Job")]
        [Alias('InputObject')]
        [Object]$Job,

        [Parameter(Mandatory=$true, ParameterSetName='Name', HelpMessage="Job Name")]
        [String[]]$Name,

        [Parameter(Mandatory=$true, ParameterSetName='Id', HelpMessage="Job Id")]
        [Int[]]$Id,

        [Parameter(Mandatory=$true, ParameterSetName='RunspacePoolId', HelpMessage="Job RunspacePoolId")]
        [System.Guid[]]$RunspacePoolId,

        [Parameter(Mandatory=$false, HelpMessage="Job State")]
        [ValidateSet(
            "NotStarted","Running","Completed","Failed",
            "Stopped","Blocked","Suspended","Disconnected",
            "Suspending","Stopping","AtBreakpoint"
        )]
        [String]$State,

        [Parameter(Mandatory=$false, HelpMessage="Timeout before a thread stops trying to gather the information")]
        [ValidateRange(1,65535)]
        [int32]$Timeout
    )
    Begin{
        $allJobs = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
        If (-not $PSBoundParameters.ContainsKey('Timeout')) {
            #TimeOut is in Milliseconds
            [int]$Timeout = 10 * 1000
        }
        Else{
            #TimeOut is in Milliseconds
            [int]$Timeout = $PSBoundParameters.TimeOut * 1000
        }
    }
    Process{
        #Add tasks to array
        If($PSCmdlet.ParameterSetName -eq 'All'){
            ForEach($_job in $MonkeyJobs){
                [void]$allJobs.Add($_job.Task)
            }
        }
        Else{
            $psn = $PSCmdlet.ParameterSetName
            $items = $PSBoundParameters[$psn]
            ForEach($item in @($items)){
                IF($PSCmdlet.ParameterSetName -eq 'Job'){
                    $rule = ('$_.{0} -eq "{1}"' -f "Id",$item.Id)
                }
                Else{
                    $rule = ('$_.{0} -eq "{1}"' -f $psn,$item)
                    If($PSBoundParameters.ContainsKey('State')){
                        $rule = ('{0} -and $_.Job.State -eq "{1}"' -f $rule, $PSBoundParameters['State'])
                    }
                }
                $sb = [ScriptBlock]::Create($rule)
                $MonkeyJob = $MonkeyJobs.Where($sb);
                $MonkeyJob.ForEach(
                    {
                        [void]$allJobs.Add($_.Task);
                    }
                );
            }
        }
    }
    End{
        #Monitor tasks
        If($allJobs.Count -gt 0){
            Try{
                While (-not [System.Threading.Tasks.Task]::WaitAll($allJobs.ToArray(), $Timeout)) {
                    Write-Verbose $script:messages.WaitJobCompletion
                }
            }
            Catch{
                #Task Error
                Write-Error $_
            }
        }
    }
}

