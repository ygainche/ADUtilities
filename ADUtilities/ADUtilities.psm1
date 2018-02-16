<#
.Synopsis
   Convert a SID to a user or group Name
.DESCRIPTION
   Convert one SID or multiple SIDs to user or group Names. Support parameter from pipeline
.EXAMPLE
   'S-1-5-32-544' | Convert-SID
.EXAMPLE
   Convert-SID S-1-5-21-1712667194-3812628584-4103615645-46577
.EXAMPLE
   Get-Content .\SIDs.txt | Convert-SID
.INPUTS
   SID as a string or table of SIDs
.OUTPUTS
   User Name (String)
#>
function convert-SID
{
    [CmdletBinding(PositionalBinding=$false)]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # SID
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias('AccountDomainSid')]
        [String]$SID
    )

    Process
    {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier ($SID)
        Try
        {
            [String]$user = ($objSID.Translate( [System.Security.Principal.NTAccount])).Value
        
        }
        Catch
        {
            $user = $null
        }
        $user
    }
}