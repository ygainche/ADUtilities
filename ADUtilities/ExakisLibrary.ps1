<# --------------------------------------------------------------------------------
   Bibliothèque de script Exakis
   =============================
   Utilisation libre de droits 
   Exakis dégage de toute responsabilité en cas de dysfonctionnement ou de mauvais usage.

   Version 1.11

   Revision History

   1.0.0    - 2016/01/01 - Serge Poncet - Création
   1.0.2	- 2017/06/29 - Yann Gainche - Ajout des switches ToHostOnly et ToLogOnly à la fonction Write-Log
   1.0.3	- 2017/06/29 - Yann Gainche - Ajout des l'affichage de l'utilisateur dans Start-Script
   1.0.4    - 2017/07/06 - Yann Gainche - Ajout de la fonction Test-Folder
   1.0.5    - 2017/08/09 - Yann Gainche - Ajout du switch keepAlive à la fonction End-Script
   1.0.6    - 2017/08/09 - Yann Gainche - Ajout de la mesure du temps d'exécution du script dans End-Script
   1.0.7    - 2017/10/23 - Yann Gainche - Ajout de la fonction Convert-SID
   1.0.8    - 2017/10/23 - Yann Gainche - Ajout de la fonction Get-SiteByIPAddress
   1.0.9    - 2017/10/23 - Yann Gainchr - Ajout de la fonction GET-ServerDNS
   1.0.10   - 2017/11/03 - Yann Gainche - Ajout de la fonction Search-ADComputerInForest qui permet une recherche par nom Netbios, Fqdn ou adresse IP
   1.0.11   - 2017/11/07 - Yann Gainche - Ajout de la fonction Get-GroupMembers qui permet de lister les membres de groupes ayant plus de 1500 membres
   1.0.12   - 2018/02/14 - Yann Gainche - Renomage de la cmdlet Get-SiteByIPAddress en Get-ADSiteByIPAddress avec un alias pour préserver l'ancien nom. Ajout de cmdletbinding

   --------------------------------------------------------------------------------
#>

New-Variable -Name c_StopWatch            -Option AllScope -Force -Value ([System.diagnostics.stopwatch]::startNew())

#region Log Management
# --------------------------------------------------------------------------------
# LOGS MANAGEMENT
# --------------------------------------------------------------------------------

Function Write-Log {
    # Paramètres
    #    Value     : chaine de caractère à afficher et enregistrer dans le log
    #    Type      : définie le type de message (information, alerte, erreur)
    #    NoNewLine : Indique si un retour à la ligne est effectué
    # Retour : aucun
    Param (
        [String] $Value = '',
        [String] $Type  = '   ',
        [Switch] $NoNewLine,
        [Switch] $ToLogOnly,
        [Switch] $ToHostOnly
    )

    $l_ColorFG = @{'   '       = 'White';
                 'Warning'     = 'Yello';
                 'Error'       = 'Red';
                 'Trap'        = 'Red';
                 'Information' = 'Cyan'
                 'Green'       = 'Green'
                 }

    $l_ColorBG = @{'   '       = "DarkBlue";
                 'Warning'     = 'Yellow';
                 'Error'       = 'Red';
                 'Trap'        = 'Red';
                 'Information' = "DarkBlue"}

    If($Type -inotin('   ', 'Warning', 'Trap', 'Error', 'Information','Green')) {
        $Type  = '   '
    }

    If($Type -eq 'Warning') {$g_Warnings++} ElseIf($Type -iin ('Error', 'Trap')) {$g_Errors++}

    If(($c_CreateLogFile) -and (!$ToHostOnly)) {
        If(!(Test-Path -Path $c_LogPath)) {
            New-Item -Path $c_LogPath -ItemType File -Force | Out-Null
        }

        Add-Content -Path $c_LogPath -Value ('{0} {1} {2}' -f (Get-Date -UFormat '%Y/%m/%d %H:%M:%S'), $Type.PadRight(12), $Value)
    }

    If (!$ToLogOnly){
#        Write-Host ('{0} {1} {2}' -f (Get-Date -UFormat '%Y/%m/%d %H:%M:%S'), $Type.PadRight(12), $Value) -ForegroundColor $l_ColorFG[$Type] -BackgroundColor $l_ColorBG[$Type] -NoNewline:$NoNewLine
        Write-Host ('{0} {1} {2}' -f (Get-Date -UFormat '%Y/%m/%d %H:%M:%S'), $Type.PadRight(12), $Value) -ForegroundColor $l_ColorFG[$Type] -NoNewline:$NoNewLine
    }
}

Function Start-Script {
    # Paramètres
    #    DisplayParameter : Affichage ou non des paramètres du script
    #    Color            : Défini l'affichage du fond d'écran pour l'exécution du script
    # Retour : aucun
    Param (
        [switch] $DisplayParameter,
        [switch] $Color
    )

    # Start execution time counter
    $c_StopWatch = [System.diagnostics.stopwatch]::startNew()
    #Backgroup color configuration
    if ($color) {
        $HOST.UI.RawUI.BackgroundColor = "DarkBlue"
        clear
    }

    Write-Log '###--------------------------------------------------------------------------------'
    Write-Log '### START'
    Write-Log "# Name     : $c_ScriptName"
    Write-Log "# Version  : $c_ScriptVersion"
    Write-Log "# Called by: $(([Security.Principal.WindowsIdentity]::GetCurrent()).name)"
    Write-Log

    If($DisplayParameter) {
        Write-Log '# Parameters'
        (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly -ErrorAction SilentlyContinue).MyCommand.Parameters.GetEnumerator() `
        | ForEach-Object {
            Try { Write-Log "#    $($_.Key) : $(Get-Variable -Name $_.Key -ValueOnly -ErrorAction Stop)" } Catch {}
        }
    }

    If($c_CheckRunAsAdmin) {
        Write-Log '# Check run as administrator'
        If((New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
            Write-Log '#    OK'
        } Else {
            Write-Log '#    Run this script with Administrator privileges' Error
            End-Script
        }
    }

    If($c_CheckMinimalVersion) {
        Write-Log "# Check PowerShell minimum version $c_MinimalVersion"
        If($c_MinimalVersion.Split('.')[0] -lt $Host.Version.Major -or ($c_MinimalVersion.Split('.')[0] -eq $Host.Version.Major -and $c_MinimalVersion.Split('.')[1] -le $Host.Version.Minor)) {
            Write-Log '#    OK'
        } Else {
            Write-Log "#    Run this script using at least PowerShell version $c_MinimalVersion. Current version is $($Host.Version)" Error
            End-Script
        }
    }

    Write-Log
}

Function End-Script {
    # Paramètres
    #    wait : Attente de l'appuie d'une touche en cas d'erreur
    # Retour : aucun
    Param(
        [switch] $wait,
        [switch] $keepAlive
    )

    Write-Log
    if ($g_Success -ge 0) {
        Write-Log "# Success    : $g_Success"
    }
    if ($g_Fail -ge 0) {
        Write-Log "# Fail       : $g_Fail"
    }
    if ($g_Items -ge 0) {
        Write-Log "# Proceeded  : $g_Items"
    }
    if (($g_Items+$g_Success+$g_Fail) -ge 0) {
        Write-Log "# "
    }
    Write-Log "# Warning(s) : $g_Warnings"
    Write-Log "# Error(s)   : $g_Errors"

    $c_StopWatch.Stop()
    Write-Log "#"
    Write-Log "# Elapsed Time:  $($c_StopWatch.Elapsed.Days) Days $($c_StopWatch.Elapsed.Hours) Hours $($c_StopWatch.Elapsed.Minutes) Minutes $($c_StopWatch.Elapsed.Seconds) Seconds" Information
    Write-Log "#"
    Write-Log '### END'
    Write-Log '###--------------------------------------------------------------------------------'

    If($g_Errors -ne 0) {
        $g_ExitCode += 1
    }

    if ($wait) {
        Read-Host -Prompt "Press enter to terminate "
    }

    if(!$keepAlive){ Exit $g_ExitCode}
}
#endregion
#region auto login management
# --------------------------------------------------------------------------------
# Autolog management

Function Set-AutoLogin {
    # Paramètres
    #    Domain   : domaine d'authentification
    #    UserName : Nom d'utilisateur
    #    Password : Mot de passe
    # Retour : aucun
    Param (
        [string] $Domain = '',
        [string] $UserName = '',
        [string] $Password= ''
    )

    
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name 'AutoAdminLogon' -Value 1
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name 'AutoLogonCount' -Value 1
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name 'DefaultUserName' -Value $UserName
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name 'DefaultPassword' -Value $Password
	If (![String]::IsNullOrEmpty($Domain)) {
		Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name 'DefaultDomainName' -Value $Domain
		Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name 'CachePrimaryDomain' -Value $Domain
	}
}

Function Remove-AutoLogin {
    # Paramètres
    #    Aucun
    # Retour : aucun
	Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name 'AutoAdminLogon' -Value 0
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name 'AutoLogonCount' -Value 0
	If ((Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name 'DefaultPassword' -ErrorAction SilentlyContinue) -ne $null) {
		Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name 'DefaultPassword'
	}
}

# --------------------------------------------------------------------------------
# Autorun

Function Set-AutoRun {
    # Paramètres
    #    Environnement : environnement d'éxécution (ordinateur ou utilisateur)
    #    Type          : Nombre d'exécution
    #    Name          : Nom de la commande
    #    Command       : Commande à exécuter
    # Retour : aucun
    Param (
        [ValidateSet("user","computer")]$Environnement = 'user',
        [ValidateSet("run","runonce")]$Type = 'run',
        [parameter(mandatory=$true)]$Name = '',
        [parameter(mandatory=$true)]$Command = ''
    )
    $Environnement = if ($Environnement -eq 'user') { "HKCU:"} else { "HKLM:" }
    $type = if ($Type -eq 'runonce') { "Runonce" } else { "Run" }
    $RunPath = $Environnement + "\Software\Microsoft\Windows\CurrentVersion"
    $RunKey = $RunPath + '\' + $Type

    try {
        Get-Item -Path $RunKey -ErrorAction Stop | Out-Null
    } catch {
        New-Item -Path $RunPath -Name $Type -Force  | Out-Null
    }
    Set-ItemProperty -LiteralPath $RunKey -Name $Name -Value $Command | Out-Null
}
#endregion

# --------------------------------------------------------------------------------
# SID management

# translate a SID from a hexadecimal representation to a standard string
Function hex2sid ($strHex) {
    # Paramètres
    #    strHex : Chaine hexadecimal à convertir
    # Retour : SID sous forme de chaine
    $intSidVersionLength = 2
    $intSubAuthorityCountLength = 2
    $intAuthorityIdentifierLength = 12
    $intSubAuthorityLength = 8
    $intStringPosition = 0
    $bytSidVersion = [byte][convert]::ToInt32($strHex.substring($intStringPosition, $intSidVersionLength),16)
    $intStringPosition = $intStringPosition + $intSidVersionLength
    $bytSubAuthorityCount=[byte][convert]::ToInt32($strHex.substring($intStringPosition, $intSubAuthorityCountLength),16)
    $intStringPosition = $intStringPosition + $intSubAuthorityCountLength
    $lngAuthorityIdentifier=[long][convert]::ToInt32($strHex.substring($intStringPosition, $intAuthorityIdentifierLength),16)
    $intStringPosition = $intStringPosition + $intAuthorityIdentifierLength
    [string]$ConvertHexStringToSidString = "S-" + $bytSidVersion + "-" + $lngAuthorityIdentifier
    Do {
        $lngTempSubAuthority = EndianReverse($strHex.substring($intStringPosition, $intSubAuthorityLength))
        $lngTempSubAuthority = [long][convert]::ToInt32($lngTempSubAuthority,16)
        $intStringPosition = $intStringPosition + $intSubAuthorityLength
        if ($lngTempSubAuthority -lt 0) {
            $lngTempSubAuthority = $lngTempSubAuthority + 4294967296
        }
        $ConvertHexStringToSidString = $ConvertHexStringToSidString+"-"+$lngTempSubAuthority
        $bytSubAuthorityCount = $bytSubAuthorityCount - 1
    } until ($bytSubAuthorityCount -eq 0)
    return $ConvertHexStringToSidString
}

Function EndianReverse ($strHex) {
    $intCounter=$strHex.length-1
    do { 
        $reverse=$reverse+$strHex.substring($intCounter-1, 2)
        $intCounter=$intCounter-2
    } until ($intCounter -eq -1)
    return $reverse
}


# Convert SID to User-Name
function convert-SID($SID)
{
    $objSID = New-Object System.Security.Principal.SecurityIdentifier ($SID)
    Try
    {
        $user = $objSID.Translate( [System.Security.Principal.NTAccount])
        
    }
    Catch
    {
        $user = $null
    }
    $user
}

# --------------------------------------------------------------------------------
# distinguished name management

Function Get-NameFromDN {
    # Paramètres
    #    DistinguishedName : distinghuised name à traiter
    # Retour : nom simple de l'objet
    Param (
        [string] $DistinguishedName
    )
    return ($DistinguishedName.Split(",")[0]).Substring(3)
}

function Get-PathFromDN {
    # Paramètres
    #    DistinguishedName : distinghuised name à traiter
    # Retour : chemin de l'objet
    Param (
        [string] $DistinguishedName
    )
    return $DistinguishedName.Substring($DistinguishedName.IndexOf(",")+1)
}

#region PowerShell
# --------------------------------------------------------------------------------
# PowerShell

function Load-Module {
    Param (
        $module
    )

    if ((Get-Module -Name $module).count -eq 0) {
        try {
            Import-Module -Name $module 
            return $true
        } catch {
            return $false
        }
    } else {
        return $true
    }
}




#endregion
# --------------------------------------------------------------------------------
# ActiveDirectory

function Test-ADOrganizationalUnit {
    Param (
        $DN ,
        [switch]$Create
    )

    try {
        Get-ADObject -Identity $DN | Out-Null
        return $true
    } catch {
        if ($Create) {
            $OUParent = $dn.substring($dn.indexof(",")+1)
            $OUName = $dn.Substring(3,$dn.indexof(",")-3)
            if (Test-ADOrganizationalUnit -DN $OUParent -Create) {
                try {
                    New-ADOrganizationalUnit -Name $OUName -Path $OUParent | Out-Null
                    Return $true
                } catch {
                    return $false
                }
            }
        } else { 
            return $false
        }
    }
}

function Test-ADGroup {
    Param (
        $Identity
    )

    try {
        Get-ADGroup -Identity $Identity | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Test-ADUser {
    Param (
        $Identity
    )

    try {
        Get-ADUser -Identity $Identity | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Test-ADObject {
    Param (
        $Identity
    )

    try {
        Get-ADUser -Identity $Identity | Out-Null
        if (Get-ADObject -Filter {samaccountname -eq $Identity}) {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

Function Search-ADComputerInForest{
    Param(
        [Parameter(Mandatory=$True)]
        [String] $computer
    )

    Process
    {
        $ADComputer = $null
        $v_DomainList = (Get-ADForest).Domains
        Switch -Regex($computer)
        {
            # Détermination du format

            # IPv4 address
            "\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b" 
            {
                $v_DomainList |% {
                    # Search AD Computer based on IPv4Address attribute
                    $ADAccount = Get-ADComputer -property * -filter { ipv4address -eq $computer } -SearchBase (Get-ADDomain $_).DistinguishedName  -SearchScope Subtree -Server (Get-ADDomain $_).PDCEmulator
                    if($ADAccount){
                        # Vérifie si l'attribut IPv4Address correspond à la résolution DNS reverse
                        if($ADAccount.DNSHostName -eq (([System.Net.Dns]::gethostentry($computer)).hostname)){
                            $ADComputer = $ADAccount
                        }
                    }
                    else {
                        $fqdn = ([System.Net.Dns]::gethostentry($computer)).hostname
                        $ADAccount = Get-ADComputer -property * -filter { DNSHostName -eq $fqdn } -SearchBase (Get-ADDomain $_).DistinguishedName  -SearchScope Subtree -Server (Get-ADDomain $_).PDCEmulator
                        if($ADAccount){ $ADComputer = $ADAccount} 
                    } 
                }
            }
            # IPv6 address
            "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
            {
                $v_DomainList |% {
                    $ADAccount = Get-ADComputer -property * -filter { ipv6address -eq $computer } -SearchBase (Get-ADDomain $_).DistinguishedName  -SearchScope Subtree -Server (Get-ADDomain $_).PDCEmulator
                    if($ADAccount){ $ADComputer = $ADAccount} 
                    }
            }            
            # FQDN
            "(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)"
            {
                $v_DomainList |% {
                    $ADAccount = Get-ADComputer -property * -filter { DNSHostName -eq $computer } -SearchBase (Get-ADDomain $_).DistinguishedName  -SearchScope Subtree -Server (Get-ADDomain $_).PDCEmulator
                    if($ADAccount){ $ADComputer = $ADAccount} 
                    }
            }
            # Netbios Name
            “^[a-zA-Z0-9-]{1,15}$"
            {
                $v_DomainList |% {
                    $ADAccount = Get-ADComputer -property * -filter { name -eq $computer } -SearchBase (Get-ADDomain $_).DistinguishedName  -SearchScope Subtree -Server (Get-ADDomain $_).PDCEmulator
                    if($ADAccount){ $ADComputer = $ADAccount} 
                    }
            }
            Default
            {
                $ADComputer = $null
            }
        } # End Switch

    $ADComputer
    } # End Proccess

} # End Function



## Return members (DN) of given AD group for large groups > 1500 members
function  Get-GroupMembers {
 
    param ([string]$group)
 
    if (-not ($group)) { return $false }
   
 
    $searcher=new-object directoryservices.directorysearcher   
    $filter="(&(objectClass=group)(cn=${group}))"
    $searcher.PageSize=1000
    $searcher.Filter=$filter
    $result=$searcher.FindOne()
 
    if ($result) {
        $members = $result.properties.item("member")
 
        ## Either group is empty or has 1500+ members
        if($members.count -eq 0) {                       
 
            $retrievedAllMembers=$false          
            $rangeBottom =0
            $rangeTop= 0
 
            while (! $retrievedAllMembers) {
 
                $rangeTop=$rangeBottom + 1499               
 
               ##this is how it would show up in AD
                $memberRange="member;range=$rangeBottom-$rangeTop"  
 
                $searcher.PropertiesToLoad.Clear()
                [void]$searcher.PropertiesToLoad.Add("$memberRange")
 
                $rangeBottom+=1500
 
                try {
                    ## should cause and exception if the $memberRange is not valid
                    $result = $searcher.FindOne() 
                    $rangedProperty = $result.Properties.PropertyNames -like "member;range=*"
                    $members +=$result.Properties.item($rangedProperty)          
                    
                     # UPDATE - 2013-03-24 check for empty group
                      if ($members.count -eq 0) { $retrievedAllMembers=$true }
                }
 
                catch {
 
                    $retrievedAllMembers=$true   ## we received all members
                }
 
            }
 
        }
 
        $searcher.Dispose()
        return $members
 
    }
    return $false  
}


function check-subnetformat([string]$subnet) {
 
 $octetsegments = $subnet.split(".")
 #Check each octet from last to first.  If an octet does not contain 0, check to see
 #if it is valid octet value for subnet masks.  Then check to make sure that all preceeding
 #octets are 255
 $foundmostsignficant = $false
 for ($i = 3; $i -ge 0; $i--) {
  if ($octetsegments[$i] -ne 0) {
   if ($foundmostsignificant -eq $true -and $octetsegments[$i] -ne 255) {
    Write-Error "The subnet mask has an invalid value"
    return $false
   } else {
    if ((255,254,252,248,240,224,192,128) -contains $octetsegments[$i]) {
     $foundmostsignficant = $true
    } else {
     Write-Error "The subnet mask has an invalid value"
     return $false
    } 
    
   }
  }
 }
 return $true
 
}


function get-subnetMask-byLength ([int]$length) {
 
 switch ($length) {
  "32" { return "255.255.255.255" }
  "31" { return "255.255.255.254" }
  "30" { return "255.255.255.252" }
  "29" { return "255.255.255.248" }
  "28" { return "255.255.255.240" }
  "27" { return "255.255.255.224" }
  "26" { return "255.255.255.192" }
  "25" { return "255.255.255.128" }
  "24" { return "255.255.255.0" }
  "23" { return "255.255.254.0" }
  "22" { return "255.255.252.0" }
  "21" { return "255.255.248.0" }
  "20" { return "255.255.240.0" }
  "19" { return "255.255.224.0" }
  "18" { return "255.255.192.0" }
  "17" { return "255.255.128.0" }
  "16" { return "255.255.0.0" }
  "15" { return "255.254.0.0" }
  "14" { return "255.252.0.0" }
  "13" { return "255.248.0.0" }
  "12" { return "255.240.0.0" }
  "11" { return "255.224.0.0" }
  "10" { return "255.192.0.0" }
  "9" { return "255.128.0.0" }
  "8" { return "255.0.0.0" }
  "7" { return "254.0.0.0"}
  "6" { return "252.0.0.0"}
  "5" { return "248.0.0.0"}
  "4" { return "240.0.0.0"}
  "3" { return "224.0.0.0"}
  "2" { return "192.0.0.0"}
  "1" { return "128.0.0.0"}
  "0" { return "0.0.0.0"}
 
 }
 
}

function get-MaskLength-bySubnet ([string]$subnet) {

 switch ($subnet) {
 "255.255.255.255" {return 32}
 "255.255.255.254" {return 31}
 "255.255.255.252" {return 30}
 "255.255.255.248" {return 29}
 "255.255.255.240" {return 28}
 "255.255.255.224" {return 27}
 "255.255.255.192" {return 26}
 "255.255.255.128" {return 25}
 "255.255.255.0"  {return 24}
 "255.255.254.0"  {return 23}
 "255.255.252.0"  {return 22}
 "255.255.248.0"  {return 21}
 "255.255.240.0" {return 20}
 "255.255.224.0" {return 19}
 "255.255.192.0" {return 18}
 "255.255.128.0" {return 17}
 "255.255.0.0"  {return 16}
 "255.254.0.0" {return 15}
 "255.252.0.0" {return 14}
 "255.248.0.0" {return 13}
 "255.240.0.0" {return 12}
 "255.224.0.0" {return 11}
 "255.192.0.0" {return 10}
 "255.128.0.0" {return 9}
 "255.0.0.0" {return 8}
 "254.0.0.0" {return 7}
 "252.0.0.0" {return 6}
 "248.0.0.0" {return 5}
 "240.0.0.0"  {return 4}
 "224.0.0.0" {return 3}
 "192.0.0.0" {return 2}
 "128.0.0.0" {return 1}
 "0.0.0.0"  {return 0}
 
 }

}

function get-networkID ([string]$ipaddr, [string]$subnetmask) {
 $ipoctets = $ipaddr.split(".")
 $subnetoctets = $subnetmask.split(".")
 $result = ""
 
 for ($i = 0; $i -lt 4; $i++) {
  $result += $ipoctets[$i] -band $subnetoctets[$i]
  $result += "."
 }
 $result = $result.substring(0,$result.length -1)
 return $result
 
}


<#
.Synopsis
   Find the Actrive Directory Subnet Associated to an IP Address
.DESCRIPTION
   Find the Actrive Directory Subnet Associated to an IP Address. IP address can be provided from the pipeline.
.EXAMPLE
   Get-ADSiteByIpAddress 192.168.1.2
.EXAMPLE
   Test-Connection MyComputer | Get-ADSiteByIPAddress
.EXAMPLE
   Get-ADSiteByIPAddress -IPAddress 10.31.0.9 -netmask 255.255.255.0
.EXAMPLE
   (get-adcomputer -filter 'Name -like "dc*"' -Properties ipv4address).ipv4address | Get-ADSiteByIPAddress
.OUTPUTS
   Active Directory Subnet name
#>
function Get-ADSiteByIPAddress {
    [CmdletBinding(SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  ConfirmImpact='low')]
    [Alias('Get-SiteByIPAddress')]
    [OutputType([String])]
    
    Param(
       [Parameter(Mandatory=$true, 
                   HelpMessage="one or more IP Address(es)",
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [validatepattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
        [Alias('IPAddress', 'Ipv4Address')] 
        $ip,

       [Parameter(Mandatory=$false, 
                   HelpMessage="Network Mask",
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false)]
        [validatepattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
        [Alias('NetworkMask')]
        $netmask,

       [Parameter(Mandatory=$false, 
                   HelpMessage="Network Mask lenght",
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false)]
        [validaterange(0,32)]
        [Alias('NetworkMaskLenght')]
        [int]$masklength
    )


    Process{
        $startMaskLength = 32
 
        #we can take network masks in both length and full octet format.  We need to use both.  LDAP searches
        #use length, and network ID generation is by full octet format.
  
        if ($netmask -ne $null) {
            if (-not(&check-subnetformat $netmask)) {
            Write-Error "Subnet provided is not a valid subnet"
            exit
            } else {
            $startmasklength = &get-MaskLength-bySubnet $netmask
            }
        }
 
 
 
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $mytopleveldomain = $forest.schema.name
        $mytopleveldomain = $mytopleveldomain.substring($mytopleveldomain.indexof("DC="))
        $mytopleveldomain = "LDAP://cn=subnets,cn=sites,cn=configuration," + $mytopleveldomain
        $de = New-Object directoryservices.DirectoryEntry($mytopleveldomain)
        $ds = New-Object directoryservices.DirectorySearcher($de)
        $ds.propertiestoload.add("cn") > $null
        $ds.propertiestoLoad.add("siteobject") > $null

 
        for ($i = $startMaskLength; $i -ge 0; $i--) {
        #loop through netmasks from /32 to /0 looking for a subnet match in AD
  
        #Go through all masks from longest to shortest
        $mask = &get-subnetMask-byLength $i
        $netwID = &get-networkID $ip $mask
  
        #ldap search for the network
        $ds.filter = "(&(objectclass=subnet)(objectcategory=subnet)(cn=" + $netwID + "/" + $i + "))"
        $fu = $ds.findone()
        if ($fu -ne $null) {
   
        #if a match is found, return it since it is the longest length (closest match)
        Write-Verbose "Found Subnet in AD at site:"
        return ($fu.properties.siteobject).split(',')[0].replace('CN=','')
        }
        $fu = $null
        }
 
        #if we have arrived at this point, the subnet does not exist in AD
 
        return $null
    }
}
# --------------------------------------------------------------------------------
# Network


function Test-TCPPort {
    Param (
        $hostname ,
        $port
    )
    $connected = $false

    $ip = [System.Net.Dns]::GetHostAddresses($hostname) |  select-object IPAddressToString -expandproperty  IPAddressToString
    $t = New-Object Net.Sockets.TcpClient

    # We use Try\Catch to remove exception info from console if we can't connect
    try {
        $t.Connect($ip,$port)
    } catch {}
    if ($t.Connected) {
        $t.Close()
        $connected = $true
    }
    return $connected
}


<#
.SYNOPSIS
    Get-ServerDNS - Gathers DNS settings from computer.
.DESCRIPTION
    This script gathers DNS settings from the specified computer(s)
.NOTES
    Author: Karl Mitschke
    Requires: Powershell V2
    Created:  05/12/2010
    Modified: 12/23/2011
.LINK
    "http://unlockpowershell.wordpress.com/2010/05/12/powershell-wmi-gather-dns-settings-for-all-servers-2/"
    "http://gallery.technet.microsoft.com/Gather-DNS-settings-from-fec23eaa"

.EXAMPLE
Get-ServerDNS.ps1
Description
-----------
Gathers DNS settings from the local computer.
.EXAMPLE
Get-ServerDNS.ps1 -Computer Exch2010
Description
-----------
Gathers DNS settings from the computer Exch2010.
.PARAMETER ComputerName
    The Computer(s) to Gather DNS settings from. If not specified, defaults to the local computer.
.PARAMETER Credential
    The Credential to use. If not specified, runs under the current security context.
#>

Function Get-ServerDNS{
    [CmdletBinding(SupportsShouldProcess=$false, ConfirmImpact='Medium')]
    param (
    [parameter(
    Mandatory=$false,
    ValueFromPipeline=$true)
    ]
    [String[]]$ComputerName=$Env:ComputerName,
    [Parameter(
    Position = 1,
    Mandatory = $false
    )]
    $Credential
    )
    BEGIN{
       #region PSBoundParameters modification
        if ($Credential -ne $null -and $Credential.GetType().Name -eq "String"){
            $PSBoundParameters.Remove("Credential") | Out-Null
            $PSBoundParameters.Add("Credential", (Get-Credential -Credential $Credential))
        }
        #endregion
        $AllServers = @()
        $ServerObj  = @()
        $Member = @{
            MemberType = "NoteProperty"
            Force = $true
        }
    }
    PROCESS{
        $PSBoundParameters.Remove("ComputerName") | Out-Null
        foreach ($StrComputer in $ComputerName){
            $NetItems = $null
            Write-Progress -Status "Working on $StrComputer" -Activity "Gathering Data"
            $ServerObj = New-Object psObject
            $ServerObj | Add-Member @Member -Name "Hostname" -Value $StrComputer
            $NetItems = @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'" -ComputerName $StrComputer @PSBoundParameters)
            $intRowNet = 0
            $ServerObj | Add-Member -MemberType NoteProperty -Name "NIC's" -Value $NetItems.Length -Force
            [STRING]$MACAddresses = @()
            [STRING]$IpAddresses = @()
            [STRING]$DNS = @()
            [STRING]$DNSSuffix = @()
            foreach ($objItem in $NetItems){
                if ($objItem.IPAddress.Count -gt 1){
                    $TempIpAdderesses = [STRING]$objItem.IPAddress
                    $TempIpAdderesses  = $TempIpAdderesses.Trim().Replace(" ", " ; ")
                    $IpAddresses += $TempIpAdderesses
                }
                else{
                    $IpAddresses += $objItem.IPAddress +"; "
                }
                if ($objItem.{MacAddress}.Count -gt 1){
                    $TempMACAddresses = [STRING]$objItem.MACAddress
                    $TempMACAddresses = $TempMACAddresses.Replace(" ", " ; ")
                    $MACAddresses += $TempMACAddresses +"; "
                }
                else{
                    $MACAddresses += $objItem.MACAddress +"; "
                }
                if ($objItem.{DNSServerSearchOrder}.Count -gt 1){
                    $TempDNSAddresses = [STRING]$objItem.DNSServerSearchOrder
                    $TempDNSAddresses = $TempDNSAddresses.Replace(" ", " ; ")
                    $DNS += $TempDNSAddresses +"; "
                }
                else{
                    $DNS += $objItem.{DNSServerSearchOrder} +"; "
                }
                if ($objItem.DNSDomainSuffixSearchOrder.Count -gt 1){
                    $TempDNSSuffixes = [STRING]$objItem.DNSDomainSuffixSearchOrder
                    $TempDNSSuffixes = $TempDNSSuffixes.Replace(" ", " ; ")
                    $DNSSuffix += $TempDNSSuffixes +"; "
                    }
                else{
                    $DNSSuffix += $objItem.DNSDomainSuffixSearchOrder +"; "
                    }
                    $SubNet = [STRING]$objItem.IPSubnet[0]
                $intRowNet = $intRowNet + 1
            }
            $ServerObj | Add-Member @Member -Name "IP Address" -Value $IpAddresses.substring(0,$ipaddresses.LastIndexOf(";"))
            $ServerObj | Add-Member @Member -Name "IP Subnet" -Value $SubNet
            $ServerObj | Add-Member @Member -Name "MAC Address" -Value $MACAddresses.substring(0,$MACAddresses.LastIndexOf(";"))
            $ServerObj | Add-Member @Member -Name "DNS" -Value $DNS
            $ServerObj | Add-Member @Member -Name "DNS Suffix Search Order" -Value $DNSSuffix
            $ServerObj | Add-Member @Member -Name "DNS Enabled For Wins" -Value $objItem.DNSEnabledForWINSResolution
            $ServerObj | Add-Member @Member -Name "Domain DNS Registration Enabled" -Value $objItem.DomainDNSRegistrationEnabled
            $ServerObj | Add-Member @Member -Name "Full DNS Registration Enabled" -Value $objItem.FullDNSRegistrationEnabled
            $ServerObj | Add-Member @Member -Name "DHCP Enabled" -Value $objItem.DHCPEnabled
            $ServerObj | Add-Member @Member -Name "DHCP Lease Obtained" -Value $objItem.DHCPLeaseObtained
            $ServerObj | Add-Member @Member -Name "DHCP Lease Expires" -Value $objItem.DHCPLeaseExpires
            $AllServers += $ServerObj
        }
    }
    END{
        Write-Output -InputObject $AllServers
    }

}

# --------------------------------------------------------------------------------
# Strings

function Remove-Diacritics {
    param ([String]$src = [String]::Empty)
    $normalized = $src.Normalize( [Text.NormalizationForm]::FormD )
    $sb = new-object Text.StringBuilder
    $normalized.ToCharArray() | % { 
        if( [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($_)
        }
    }
    return $sb.ToString()
}

# --------------------------------------------------------------------------------
# Files & Folders

<# 

  Function: Test-Folder

  Check if a folder exists. If -create switch is used, create the folder as well as parent folders.

#>
function Test-Folder {
    Param (
        $Path ,
        [switch]$Create
    )

    If ($Path.Length -eq 0) { Return $False}


    if (Test-Path -Path $Path) {
        return $true
    }
    elseif ($Create) {
        if (Test-Folder -Path (Split-Path -Path $path -Parent) -Create) {
            Try{
                New-Item -Path (Split-Path -Path $path -Parent) -Name (Split-Path -Path $path -Leaf) -ItemType directory -EA Stop | out-null
                Return $true
            }
            Catch{
                Return $false
            }
         }
         else {
            Return $false
         }
    } 
    else { 
        return $false
    }
}


Function Select-Folder {
    Param (
        [String]$message = 'Sélectionner un dossier',
        [String] $path = (Get-Location).path
    )

    $object = New-Object -comObject Shell.Application  

    $folder = $object.BrowseForFolder(0, $message, 0, $path) 
    if ($folder -ne $null) { 
        $folder.self.Path 
    } 
} 

function Select-File {
	param(
        [string]$Title = 'Sélectionner un fichier' ,
        [string]$Directory = (Get-Location).Path,
        [string]$Filter="All Files (*.*)|*.*"
    )

	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
	$objForm = New-Object System.Windows.Forms.OpenFileDialog
	$objForm.InitialDirectory = $Directory
	$objForm.Filter = $Filter
	$objForm.Title = $Title
	$Show = $objForm.ShowDialog()
	If ($Show -eq "OK") {
		Return $objForm.FileName
	} Else {
		return ""
	}
}


function Import-table {
    # Paramètres
    #    Hashtable : hastable qui va contenir le tableau de référence
    #    File      : Fichier contenant la table à importer
    #    Delimiter : Delimiter utilisé dans le fichier à importer pour séparer les colonnes
    #    Columns   : entetes des colonnes qui doivent être importées dans le hashtable. La 1ère entrée endique l'index, la seconde les données
    #    Header    : tableau indiquant les entetes de colonnes dans le cas ou le fichier en entrée n'a pas d'entete de colonne
    # Retour : Hastable complété à partir des informations du fichier d'import
   Param(
        $HashTable,
        $file,
        [string]$Delimiter = ";" ,
        $Columns,
        $header
    )
    if($Columns.Count -ne 2) { return }
    if ($header) {
        Import-Csv -Path $file -Delimiter $Delimiter -Header $header| foreach { $HashTable[$_.($Columns[0])] = $_.($Columns[1]) }
    } else {
        Import-Csv -Path $file -Delimiter $Delimiter | foreach { $HashTable[$_.($Columns[0])] = $_.($Columns[1]) }
    }
}


# --------------------------------------------------------------------------------
# New Password


function New-SWRandomPassword {
    <#
    .Synopsis
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .DESCRIPTION
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .EXAMPLE
       New-SWRandomPassword
       C&3SX6Kn

       Will generate one password with a length between 8  and 12 chars.
    .EXAMPLE
       New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
       7d&5cnaB
       !Bh776T"Fw
       9"C"RxKcY
       %mtM7#9LQ9h

       Will generate four passwords, each with a length of between 8 and 12 chars.
    .EXAMPLE
       New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
       3ABa

       Generates a password with a length of 4 containing atleast one char from each InputString
    .EXAMPLE
       New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
       3ABa

       Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from 
       the string specified with the parameter FirstChar
    .OUTPUTS
       [String]
    .NOTES
       Written by Simon Wåhlin, blog.simonw.se
       I take no responsibility for any issues caused by this script.
    .FUNCTIONALITY
       Generates random passwords
    .LINK
       http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
   
    #>
    [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({$_ -gt 0})]
        [Alias('Min')] 
        [int]$MinPasswordLength = 8,
        
        # Specifies maximum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({
                if($_ -ge $MinPasswordLength){$true}
                else{Throw 'Max value cannot be lesser than min value.'}})]
        [Alias('Max')]
        [int]$MaxPasswordLength = 12,

        # Specifies a fixed password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='FixedLength')]
        [ValidateRange(1,2147483647)]
        [int]$PasswordLength = 8,
        
        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!"#%&'),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,
        
        # Specifies number of passwords to generate.
        [ValidateRange(1,2147483647)]
        [int]$Count = 1
    )
    Begin {
        Function Get-Seed{
            # Generate a seed for randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToUInt32($RandomBytes, 0)
        }
    }
    Process {
        For($iteration = 1;$iteration -le $Count; $iteration++){
            $Password = @{}
            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

            # Set password length
            if($PSCmdlet.ParameterSetName -eq 'RandomLength')
            {
                if($MinPasswordLength -eq $MaxPasswordLength) {
                    # If password length is set, use set length
                    $PasswordLength = $MinPasswordLength
                }
                else {
                    # Otherwise randomize password length
                    $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if($PSBoundParameters.ContainsKey('FirstChar')){
                $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
            }
            # Randomize one char from each group
            Foreach($Group in $CharGroups) {
                if($Password.Count -lt $PasswordLength) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed                        
                    }
                    $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                }
            }

            # Fill out with chars from $AllChars
            for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                $Index = Get-Seed
                While ($Password.ContainsKey($Index)){
                    $Index = Get-Seed                        
                }
                $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
            }
            Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
        }
    }
}