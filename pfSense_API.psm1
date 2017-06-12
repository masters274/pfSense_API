<#
        .Synopsis
        pfSense management functions. 

        .DESCRIPTION
        Haven't been able to find another API, or command line management for pfSense
        
        .NOTES
        It runs on Linux guys.... there shouldn't be a need for these functions...
        
        .COMPONENT
        Security, Networking, Firewall
        
        .FUNCTIONALITY
        pfSense task automation and scriptability
#>


#region Verion Info

<#
        Version 0.1
        - Day one - it's my birfday!
#>

#endregion


#region Prerequisites

# All modules require the core
If (!(Get-Module -Name core))
{
    Try
    {
        Import-Module -Name 'core' -ErrorAction Stop
    }

    Catch
    {
        Try
        {
            $uriCoreModule = 'https://raw.githubusercontent.com/masters274/Posh_Repo/master/Modules/Core/core.psm1'
    
            $moduleCode = (Invoke-WebRequest -Uri $uriCoreModule -UseBasicParsing).Content
            
            Invoke-Expression -Command $moduleCode
        }
    
        Catch
        {
            Write-Error -Message ('Failed to load {0}, due to missing core module' -f $PSScriptRoot)
        }
    }
}

#endregion


#region Functions


Function Connect-pfSense
{
    <#
            .DESCRIPTION
            Authenticates to a pfSense server and returns the session variable
    #>
    [CmdLetBinding()]
    Param
    (
        [Parameter(
                Mandatory=$true,
                Position=0,
                HelpMessage='Hostname of pfSesense server'
        )]
        [Alias('HostName')]
        [String] $Server,
        
        [Parameter(
                Mandatory=$true,
                Position=1,
                HelpMessage='Credentials for administering pfSense'
        )]
        [PSCredential] $Credential,
        
        [Switch] $NoTLS # Not recommended
    )
    
    Begin
    {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process
    {
        # Variables
        $uri = 'https://{0}/index.php' -f $Server
        
        If ($NoTLS) # highway to tha Danger Zone!!!
        {
            $uri = $uri -Replace "^https:",'http:'
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
        
        $request = iwr -Uri $uri
        
        $webCredential = @{login='Login'
            usernamefld=$Credential.GetNetworkCredential().UserName
            passwordfld=$Credential.GetNetworkCredential().Password
            __csrf_magic=$($request.InputFields[0].Value)
        }

        iwr -Uri $uri -Body $webCredential -Method Post -SessionVariable pfWebSession | Out-Null
        
        $pfWebSession
    }
}


Function Add-pfSenseUser
{
    <#
            .Synopsis
            Adds a new user via pfSense user management page

            .DESCRIPTION
            Great for automating the turn up of new remote users

            .EXAMPLE
            $Creds = Get-Credential
            $pfs = Connect-pfSense -Server firewall.local -Credential $Creds
            Add-pfSenseUser -Session $pfs -Server firewall.local -UserName 'player1' -Password 'MySecretPassword' -FullName 'Player One'

            Creates a user account on the pfSense firewall named "firewall.local"

            .NOTES
            For the certificate, you'll need to get the CA's reference ID. This is located in the page source
            code of either the CA itself, or on the Add User Management Page. This can be found by visiting one of
            these pages, right-click and select view page source, the perfrom a search for caref. 
            
            I'll write something to get this later... an example of this: 4813b1f414fec
            
            <div>
                <select class="form-control" name="caref" id="caref">
                <option value="4813b1f414fec">pfSenseCertificateAuthority</option>
            </div>
    #>

    [CmdLetBinding()]
    [CmdletBinding(DefaultParameterSetName='NoCert')]
    Param
    (
        [Parameter(
                Mandatory=$true,
                Position=0,
                HelpMessage='Hostname of pfSesense server'
        )]
        [Alias('HostName')]
        [String] $Server,
        
        [Parameter(
                Mandatory=$true,
                Position=1,
                HelpMessage='Valid/active websession to server'
        )]
        [Microsoft.PowerShell.Commands.WebRequestSession] $Session,
        
        [Parameter(Mandatory=$true,ParameterSetName="Certificate",
                HelpMessage='User name', Position=2
        )]
        [String] $UserName,
        
        [Parameter(Mandatory=$true,ParameterSetName="Certificate",
                HelpMessage='Password for the user', Position=3
        )]
        [String] $Password,
        
        [Parameter(Mandatory=$true,ParameterSetName="Certificate",
                HelpMessage='Display name for the user', Position=4
        )]
        [String] $FullName,
        
        [Switch] $Certificate,
        
        [Parameter(Mandatory=$false,ParameterSetName="NoCert")]
        [Parameter(Mandatory=$true,ParameterSetName="Certificate",
                HelpMessage='Name of the CA'
        )]
        [String] $CA,
        
        [Int] $KeyLength = 2048,
        
        [Int] $LifeTime = 3650,
        
        [Switch] $NoTLS # Not recommended
    )
    
    Begin
    {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process
    {
        # Variables
        $uri = 'https://{0}/system_usermanager.php' -f $Server
        
        If ($NoTLS) # highway to tha Danger Zone!!!
        {
            $uri = $uri -Replace "^https:",'http:'
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
        
        # pfSense requires a lot of magic.... ++ foreach POST 
        $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $Session
        
        $dictPostData = @{
            __csrf_magic=$($request.InputFields[0].Value)
            usernamefld=$UserName
            passwordfld1=$Password
            passwordfld2=$Password
            descr=$FullName
            utype='user' 
            save='Save'
        } # Change the utype to 'system' to create a protected system user
        
        $dictCertData = @{ # Extra form fields when requesting a certificate for the user
            showcert='yes'
            name="$($UserName)_cert"
            caref=$CA
            keylen=$KeyLength
            lifetime=$LifeTime
        }
            
        If ($Certificate) # Should we request a cert from the CA?
        {
            $dictPostData += $dictCertData
        }
        
        # submit/post the form to the server
        $uri += '?act=new'
        Invoke-DebugIt -Console -Message '[INFO]' -Value ('Post URI: {0}' -f $uri)
        
        Try
        {
            Invoke-WebRequest -Uri $uri -Method Post -Body $dictPostData -WebSession $Session -EA Stop
        }
        
        Catch
        {
            Write-Error -Message 'Something went wrong submitting the form'
        }
    }
    
    End
    {
     
    }
}


Function Remove-pfSenseUser
{
    
}


Function Export-pfSenseUserCert
{
    
}


Function Revoke-pfSenseUserCert
{
    
}


Function Backup-pfSenseConfig
{
    <#
            .Synopsis
            Backup your pfSense firewall

            .DESCRIPTION
            Long description

            .EXAMPLE
            $Creds = Get-Credential
            $pfs = Connect-pfSense -Server firewall.local -Credential $Creds
            Backup-pfSenseConfig -Server firewall.local -Session $pfs
    #>
    
    [CmdLetBinding()]
    Param(
        [Parameter(
                Mandatory=$true,
                Position=0,
                HelpMessage='Hostname/IP of pfSesense server'
        )]
        [Alias('HostName')]
        [String] $Server,
        
        [Parameter(
                Mandatory=$true,
                Position=1,
                HelpMessage='Valid/active websession to server'
        )]
        [Microsoft.PowerShell.Commands.WebRequestSession] $Session,
        
        [Parameter(Position=2)]
        [ValidateScript({
                    try {
                        $Folder = Get-Item $_ -ErrorAction Stop
                    } catch [System.Management.Automation.ItemNotFoundException] {
                        Throw [System.Management.Automation.ItemNotFoundException] "${_} Maybe there are network issues?"
                    }
                    if ($Folder.PSIsContainer) {
                        $True
                    } else {
                        Throw [System.Management.Automation.ValidationMetadataException] "The path '${_}' is not a container."
                    }
        })]
        [String] $FilePath = ('{0}\{1}_pfSenseBackup.xml' -f $($PWD.Path), $(Get-Date -UFormat '%Y%m%d_%H%M%S')),
        
        [String] $EncryptPassword,
        
        [Switch] $NoTLS # Not recommended
    )
    
    Begin
    {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process
    {
        # Variables
        $uri = 'https://{0}/diag_backup.php' -f $Server
    
        If ($NoTLS) # highway to tha Danger Zone!!!
        {
            $uri = $uri -Replace "^https:",'http:'
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
    
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
    
        # pfSense requires a lot of magic.... ++ foreach POST 
        $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $Session
    
    
        $dictPostData = @{
            __csrf_magic=$($request.InputFields[0].Value)
            donotbackuprrd='yes'
            download='Download configuration as XML'
        }
        
        If ($EncryptPassword)
        {
            $dictSecurity = @{
                encrypt_password="$EncryptPassword" 
            }
        
            $dictPostData += $dictSecurity
        
            Invoke-DebugIt -Console -Message '[INFO]' -Value 'Encryption password set'
        }
    
        Try
        {
            $rawRequest = Invoke-WebRequest -Uri $uri -Method Post -Body $dictPostData -WebSession $Session -EA Stop
        }
        
        Catch
        {
            Write-Error -Message 'Something went wrong submitting the form'
        }
    
        If ($rawRequest)
        {
            Invoke-DebugIt -Console -Message '[INFO]' -Value ('Output file: {0}' -f $FilePath)
            ConvertFrom-HexToFile -HexString $rawRequest.Content -FilePath $FilePath
        }
    
        Else
        {
            Write-Error -Message 'Failed to read the output file'
        }
    }
    
    End
    {
        
    }
}


#endregion

