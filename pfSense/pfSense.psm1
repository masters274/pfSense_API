<#
        .Synopsis
        pfSense management functions built for pfSense version 2.x

        .DESCRIPTION
        Haven't been able to find another API, or command line management for pfSense
        
        .NOTES
        It runs on Linux guys.... there shouldn't be a need for these functions...
        
        .COMPONENT
        Security, Networking, Firewall
        
        .FUNCTIONALITY
        pfSense task automation and scriptability
#>

#region Prerequisites

# All modules require the core

<#
        Great news! The core module is now installed automatically when installed from PSGallery
#>

#endregion

#================================================= MEAT! =========================================================#

#region Connection functions


Function Connect-pfSense {
    <#
            .DESCRIPTION
            Authenticates to a pfSense server and returns the session variable
            
    #>
    [CmdLetBinding()]
    Param
    (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            HelpMessage = 'Hostname of pfSesense server'
        )]
        [Alias('HostName')]
        [String] $Server,
        
        [Parameter(
            Mandatory = $true,
            Position = 1,
            HelpMessage = 'Credentials for administering pfSense'
        )]
        [PSCredential] $Credential,
        
        [Switch] $NoTLS, # Not recommended
        
        [Switch] $IgnoreCertificateErrors
    )
    
    Begin {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
        # Is -Force set?
        # TODO: use to avoid asking if we should ignore self-signed web certs
        $Script:boolForce = $PSBoundParameters.Force.IsPresent

        # pfSense requires TLS1.2 This is not an available security protocol in Invoke-WebRequest by default
        # TODO: use available function  (Set-WebSecurityProtocol)
        If ([Net.ServicePointManager]::SecurityProtocol -notmatch 'TLS12' -and -not $NoTLS) {
            [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::TLS12
        }
        
        <#
                .NOTE: might be a good idea to add this to your $profile. Default is SSLv3 for Posh web commands!!!

                # Security protocols for web calls. removes SSL3 and TLS1.0
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS11
                [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::TLS12

                ...Just a suggestion
        #>
        
        # TODO: use available function  (Set-WebCertificatePolicy)
        # Warn the user user that security will be degraded, and ask if they would like to proceed. 
        # Check if they have the proper version of core use the function to Set-WebCertificatePolicy
        # Require that core be updated
        # Add a note on how to revert the security policy back to the original, without restarting PowerShell
        If ($IgnoreCertificateErrors) {
            Try {
                Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;

public class InSecureWebPolicy : ICertificatePolicy 
{
    public bool CheckValidationResult(ServicePoint sPoint, X509Certificate cert,WebRequest wRequest, int certProb)
    {
        return true;
    }
}
'@
            }
            Catch
            {}
            
            $pol = [System.Net.ServicePointManager]::CertificatePolicy
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName InSecureWebPolicy
            
            <#
                    .NOTE: There is a timeout value to using this option. At the end of this function the
                    policy is returned to its original configuration. PowerShell takes a little time, almost
                    like cache, to recognize the reversion. Therefore this option is only good for fast 
                    scripting, and not for coding on the command line. 

                    It is recommended that you import the cert into your trusted certificates store
            #>
            
        }
    }
    
    Process {
        # Variables
        $uri = 'https://{0}/index.php' -f $Server
        $pfWebSession = $null
        $retObject = @()
        $dictOptions = @{
            host  = $Server
            NoTLS = $([bool] $NoTLS)
        }
        
        If ($NoTLS) { # highway to tha Danger Zone!!!
            $uri = $uri -Replace "^https:", 'http:'
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
        
        $request = iwr -Uri $uri
        
        $webCredential = @{login = 'Login'
            usernamefld          = $Credential.GetNetworkCredential().UserName
            passwordfld          = $Credential.GetNetworkCredential().Password
            __csrf_magic         = $($request.InputFields[0].Value)
        }

        Invoke-WebRequest -Uri $uri -Body $webCredential -Method Post -SessionVariable pfWebSession | Out-Null
        
        $retObject += $pfWebSession
        $retObject += $dictOptions
        
        $retObject
    }
    
    End {
        [System.Net.ServicePointManager]::CertificatePolicy = $pol
    }
}


#endregion

#region User functions


Function Add-pfSenseUser {
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
    [CmdletBinding(DefaultParameterSetName = 'NoCert')]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $true, Position = 1,
            HelpMessage = 'User name'
        )] [String] $UserName,
        
        [Parameter(Mandatory = $true, Position = 2,
            HelpMessage = 'Password for the user'
        )] [Alias('Password')]
        [String] $UserPass,
        
        [Parameter(Mandatory = $true, Position = 3,
            HelpMessage = 'Display name for the user'
        )] [String] $FullName,
        
        [Parameter(ParameterSetName = 'Certificate')]
        [Switch] $Certificate,
        
        [Parameter(Mandatory = $false, ParameterSetName = "NoCert")]
        [Parameter(Mandatory = $true, ParameterSetName = "Certificate",
            HelpMessage = 'Name of the CA'
        )] [String] $CA,
        
        [Int] $KeyLength = 2048,
        
        [Int] $LifeTime = 3650,

        [ValidateSet('sha1', 'sha224', 'sha256', 'sha384', 'sha512')]
        [String] $DigestAlgorithm = 'sha256',
        
        [Switch] $Quiet # No output upon completion
    )
    
    Begin {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
        $Password = $UserPass
    }
    
    Process {
        # Variables
        $Server = $Session.host
        [bool] $NoTLS = $Session.NoTLS 
        [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Session[0]
        $uri = 'https://{0}/system_usermanager.php' -f $Server
        
        If ($NoTLS) { # highway to tha Danger Zone!!!
            $uri = $uri -Replace "^https:", 'http:'
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
        
        # pfSense requires a lot of magic.... ++ foreach POST 
        $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
        
        $dictPostData = @{
            __csrf_magic     = $($request.InputFields[0].Value)
            usernamefld      = $UserName
            passwordfld1     = $Password
            passwordfld2     = $Password
            descr            = $FullName
            utype            = 'user' 
            save             = 'Save'
            
            # Needed for version >= 2.4.4
            dashboardcolumns = 2
            webguicss        = 'pfSense.css'
            
        } # Change the utype to 'system' to create a protected system user
        
        $dictCertData = @{ # Extra form fields when requesting a certificate for the user
            showcert    = 'yes'
            name        = "$($UserName)_cert"
            caref       = $CA
            keylen      = $KeyLength
            lifetime    = $LifeTime
            digest_alg  = $DigestAlgorithm
        }
            
        If ($Certificate) { # Should we request a cert from the CA?
            $dictPostData += $dictCertData
        }
        
        # submit/post the form to the server
        $uri += '?act=new'
        Invoke-DebugIt -Console -Message '[INFO]' -Value ('Post URI: {0}' -f $uri)
        
        Try {
            $rawRet = Invoke-WebRequest -Uri $uri -Method Post -Body $dictPostData -WebSession $webSession -EA Stop |
            Out-Null
            
            If ($rawRet.StatusCode -eq 200 -and -not $Quiet) {
                Invoke-DebugIt -Console -Message 'Success' -Force -Color 'Green' `
                    -Value ('User: {0}, created successfully!' -f $FullName)
            }
        }
        
        Catch {
            Write-Error -Message 'Something went wrong submitting the form'
        }
    }
    
    End {
     
    }
}


Function Get-pfSenseUser {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [AllowNull()]
        [Parameter(Position = 1)] 
        [String] $UserName,
        
        [Switch] $CertInfo,
        
        [Switch] $Detail
    )
    
    Begin {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
        Function Script:Where-Deleteable {
            param
            (
                [Object]
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Data to filter")]
                $InputObject
            )
            process {
                if ($InputObject.title -match 'Delete user') {
                    $InputObject
                }
            }
        }
    }
    
    Process {
        # Variables
        $objUsers = @()
        $objUsersDetail = @()
        
        #--------------------------------------------------------------------------------------#

        $Server = $Session.host
        [bool] $NoTLS = $Session.NoTLS 
        [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Session[0]
        $uri = 'https://{0}/system_usermanager.php' -f $Server
        
        If ($NoTLS) { # highway to tha Danger Zone!!!
            $uri = $uri -Replace "^https:", 'http:'
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
        
        # pfSense requires a lot of magic.... ++ foreach POST 
        $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
        
        # Get a list of deletable users. 
        $users = $request.Links | Where-Deleteable # Note: can't delete yourself
        
        # Build an array with usernames and IDs, which can be deleted by the current user. 
        Foreach ($user in $users) {
            $uname = $user.href.Split(';').Replace('&amp', '').Trim() -match 'username'
            $uid = $user.href.Split(';').Replace('&amp', '').Trim() -match 'userid'
            
            
            $objBuilder = New-Object -TypeName PSObject
            $objBuilder | Add-Member -MemberType NoteProperty -Name 'Username' -Value $($uname.Split('=')[1])
            $objBuilder | Add-Member -MemberType NoteProperty -Name 'UserID' -Value $($uid.Split('=')[1])
            
            If ($CertInfo) {
                
                $userEditUri = $uri + ('?act=edit&userid={0}' -f $($uid.Split('=')[1]))
                $userReq = Invoke-WebRequest -Uri $userEditUri -WebSession $webSession -Method Get
                
                $cert = $userReq.ParsedHtml.frames.document.body.outerHTML.Split("`n") | 
                Where-Object { $_ -match "Remove this certificate association" }
                    
                If ($cert) {
                    #$certName = ''
                    $boolCert = $true
                }
                
                Else {
                    #$certName = $null
                    $boolCert = $false
                }
                
                $objBuilder | Add-Member -MemberType NoteProperty -Name 'Cert' -Value $boolCert
                #$objBuilder | Add-Member -MemberType NoteProperty -Name 'CertName' -Value $certName
                
            }
            
            $objUsers += $objBuilder
        }
        
        If ($Detail) {
            $tempFile = $env:TEMP + '\' + [guid]::NewGuid().guid + '.xml'

            [xml] $xmlFile = Backup-pfSenseConfig -Session $Session -OutputXML
            
            Foreach ($user in $xmlFile.pfsense.system.user) {
                # Cert info if exists
                $objCert = $xmlFile.pfsense.cert | ? { $_.refid -eq $user.cert }
                $objCA = $xmlFile.pfsense.ca | ? { $_.refid -eq $objCert.caref }
                $uid = $objUsers | ? { $_.username -eq $user.name } | % { $_.userid }
                $objCrl = $xmlFile.pfsense.crl | ? { $_.caref -eq $objCA.refid }
                
                
                $objBuilder = New-Object -TypeName PSObject
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'Username' -Value $user.name
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'System_UID' -Value $user.uid
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'UserID' -Value $uid
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'FullName' -Value $user.descr.'#cdata-section'
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'Expiration' -Value $user.expires

                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'User_Type' -Value $user.scope
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'Cert' -Value $objCert.descr.'#cdata-section'
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'Cert_ID' -Value $user.cert
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'CA' -Value $objCA.descr.'#cdata-section'
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'CA_ID' -Value $objCA.refid
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'CRL' -Value $objCrl.descr.'#cdata-section'
                
                $objBuilder | 
                Add-Member -MemberType NoteProperty -Name 'CRL_ID' -Value $objCrl.refid
                
                
                $objUsersDetail += $objBuilder
            }
            
            If ($UserName) {
                Try {
                    $objUsersDetail | Where-Object { $_.Username -eq $UserName }
                }
                
                Catch {
                    Write-Host -ForegroundColor Red "Username $UserName not found"
                    
                    $objUsersDetail
                }
            }
            
            Else {
                $objUsersDetail
            }
        }
        
        Else {
            If ($UserName) {
                Try {
                    $objUsers | Where-Object { $_.Username -eq $UserName }
                }
                
                Catch {
                    Write-Host -ForegroundColor Red "Username $UserName not found"
                    
                    $objUsers
                }
            }
            
            Else {
                $objUsers
            }
        }
    }
    
    End {
        Remove-Variable -Name xmlFile -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        [GC]::Collect()
    }        
}


Function Remove-pfSenseUser {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $true, Position = 1,
            HelpMessage = 'User name'
        )] [String] $UserName,
        
        [Switch] $RevokeCert,
        
        [Switch] $Quiet
    )
    
    Begin {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process {
        # Variables
        $Server = $Session.host
        [bool] $NoTLS = $Session.NoTLS 
        [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Session[0]
        $uri = 'https://{0}/system_usermanager.php' -f $Server
        
        
        If ($NoTLS) { # highway to tha Danger Zone!!!
            $uri = $uri -Replace "^https:", 'http:'
            
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
        
        # pfSense requires a lot of magic.... ++ foreach POST 
        $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
        
        # Get a list of deletable users. 
        $objUser = Get-pfSenseUser -Session $Session -Detail -UserName $UserName
        
        # Get the ID of the username to be deleted. 
        Try {
            [bool] (!($objUser.UserID -eq $null))
            
            Invoke-DebugIt -Console -Message '[INFO]' -Value ('User ID found: {0}' -f $objUser.UserID)
        }
        
        Catch {
            Write-Error -Message `
                'Failed to get the user ID for the username provided. Check the username, and try again'
            return
        }
        
        
        If ($RevokeCert) {
            Revoke-pfSenseUserCert -Session $Session -UserName $UserName -Reason 'Cessation of Operation'
        }
        
        
        # Dictionary submitted as body in our POST request
        $dictPostData = @{
            __csrf_magic     = $($request.InputFields[0].Value)
            'delete_check[]' = $($objUser.UserID)
            'dellall'        = 'dellall'
        }
        
        Try {
            $rawRet = Invoke-WebRequest -Uri $uri -Method Post -Body $dictPostData -WebSession $webSession -EA Stop |
            Out-Null

            If ($rawRet.StatusCode -eq 200 -and -not $Quiet) {
                Invoke-DebugIt -Console -Message 'Success' -Force -Color 'Green' `
                    -Value ('User: {0}, deleted successfully!' -f $UserName)
            }
        }
        
        Catch {
            Write-Error -Message 'Something went wrong submitting the form'
        }
    }
    
    End {
     
    }
}


Function Export-pfSenseUserCert {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $true, Position = 1,
            HelpMessage = 'User name'
        )] [String] $UserName,
        
        [Parameter(Position = 2)]
        [ValidateSet('Cert', 'Key', 'P12')]
        [String] $CertAction = 'Cert',
        
        [Parameter(Position = 3)]
        [ValidateScript({
                try {
                    $Folder = Get-Item $($_ | Split-Path -Parent) -ErrorAction Stop
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    Throw [System.Management.Automation.ItemNotFoundException] "${_} Maybe there are network issues?"
                }
                if ($Folder.PSIsContainer) {
                    $True
                }
                else {
                    Throw [System.Management.Automation.ValidationMetadataException] "The path '${_}' is not a container."
                }
            })]
        [String] $FilePath
    )
    
    Begin {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
        Function Script:Extract-WebTable {
            # code from Lee Holmes 
            # http://www.leeholmes.com/blog/2015/01/05/extracting-tables-from-powershells-invoke-webrequest/
            Param
            (
                [Parameter(Mandatory = $true)]
                [Microsoft.PowerShell.Commands.HtmlWebResponseObject] $WebRequest,

                [Parameter(Mandatory = $true)]
                [int] $TableNumber
            )

            ## Extract the tables out of the web request

            $tables = @($WebRequest.ParsedHtml.getElementsByTagName("TABLE"))

            $table = $tables[$TableNumber]

            $titles = @()

            $rows = @($table.Rows)

            ## Go through all of the rows in the table

            Foreach ($row in $rows) {
                $cells = @($row.Cells)

                ## If we've found a table header, remember its titles

                If ($cells[0].tagName -eq "TH") {
                    $titles = @($cells | ForEach-Object { ("" + $_.InnerText).Trim() })

                    continue
                }

                ## If we haven't found any table headers, make up names "P1", "P2", etc.

                If (-not $titles) {
                    $titles = @(1..($cells.Count + 2) | ForEach-Object { "P$_" })
                }

                ## Now go through the cells in the the row. For each, try to find the

                ## title that represents that column and create a hashtable mapping those

                ## titles to content

                $resultObject = [Ordered] @{}

                For ($intCounter = 0; $intCounter -lt $cells.Count; $intCounter++) {

                    $title = $titles[$intCounter]

                    If (-not $title) { continue }

                    $resultObject[$title] = ("" + $cells[$intCounter].InnerText).Trim()

                }

                ## And finally cast that hashtable to a PSCustomObject

                [PSCustomObject] $resultObject
            }
        }
    }
    
    Process {
        # Variables
        $Server = $Session.host
        [bool] $NoTLS = $Session.NoTLS 
        [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Session[0]
        $uri = 'https://{0}/system_certmanager.php' -f $Server
        
        
        If ($NoTLS) { # highway to tha Danger Zone!!!
            $uri = $uri -Replace "^https:", 'http:'
          
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
        
        # # Get the page contents so we can parse the table. We'll need the iterated ID based on the web table.
        # $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
        
        # $objTable = Extract-WebTable -WebRequest $request -TableNumber 0
        
        # # get the ID of the user on the page
        # $userID = $objTable.IndexOf(($objTable | Where-Object {$_.name -match $UserName})[0])

        $userId = Get-pfSenseUser -Session $Session -UserName $UserName -Detail | Select-Object -ExpandProperty Cert_ID
        
        Switch ($CertAction) {
            Key {
                $uri += ('?act=key&id={0}' -f $userID)
                $fExt = 'key'
                Break
            }
            
            P12 {
                $uri += ('?act=p12&id={0}' -f $userID)
                $fExt = 'p12'
                Break
            }
            
            Default {
                $uri += ('?act=exp&id={0}' -f $userID)
                $fExt = 'crt'
                Break
            }
        }
        
        If (!$FilePath) {
            [String] $FilePath = ('{0}\{1}_pfSenseUserCertificate.{2}' -f $($PWD.Path), $UserName, $fExt)
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value ('Export path = {0}' -f $FilePath) -Force 
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value ('URI = {0}' -f $uri.ToString())

        $exRequest = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
        
        ConvertFrom-HexToFile -HexString $exRequest.Content -FilePath $FilePath
    }
    
    End {
     
    }
}


Function Revoke-pfSenseUserCert {
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $true, Position = 1,
            HelpMessage = 'User name'
        )] [String] $UserName, 
        
        [ValidateSet('No Status (default)', 'Unspecified', 'Key Compromise', 'CA Compromise', 
            'Affiliation Change', 'Superseded', 'Cessation of Operation', 'Certificate Hold'
        )] [String] $Reason = 'Unspecified',
        
        [Switch] $Quiet
    )
    
    Begin {
        
    }
    
    Process {
        # Variables
        $Server = $Session.host
        [bool] $NoTLS = $Session.NoTLS 
        [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Session[0]
        $user = Get-pfSenseUser -Session $Session -Detail -UserName $UserName
    
        $dictReason = @{
            'No Status (default)'    = '-1'
            'Unspecified'            = 0
            'Key Compromise'         = 1
            'CA Compromise'          = 2
            'Affiliation Changed'    = 3
            'Superseded'             = 4
            'Cessation of Operation' = 5
            'Certificate Hold'       = 6
        }
    
        If ($user.count -gt 1 -or $user -eq $null) {
            Write-Error -Message ('Failed to get username {0}' -f $UserName)
            Return
        }
    
        If (!$user.CRL_ID) {
            Write-Error -Message ('No CRL for {0}' -f $UserName)
            Return
        }
    
        $uri = 'https://{0}/system_crlmanager.php?act=edit&id={1}' -f $Server, $user.CRL_ID
        
        If ($NoTLS) { # highway to tha Danger Zone!!!
            $uri = $uri -Replace "^https:", 'http:'
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
        
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
    
    
        # pfSense requires a lot of magic.... ++ foreach POST 
        $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
    
        # Dictionary submitted as body in our POST request
        $dictPostData = @{
            __csrf_magic = $($request.InputFields[0].Value)
            certref      = $($user.Cert_ID)
            crlreason    = $($dictReason["$Reason"])
            submit       = 'Add'
            id           = $($user.CRL_ID)
            act          = 'addcert'
            crlref       = $($user.CRL_ID)
        }
    
        Try {
            $rawRet = Invoke-WebRequest -Uri $uri -Method Post -Body $dictPostData -WebSession $webSession -EA Stop |
            Out-Null
            
            If ($rawRet.StatusCode -eq 200 -and -not $Quiet) {
                Invoke-DebugIt -Console -Message 'Success' -Force -Color 'Green' `
                    -Value ('Certificate: {0}, revoked successfully!' -f $UserName)
            }
        }
        
        Catch {
            Write-Error -Message 'Something went wrong submitting the form'
        }
    }
    
    End {
    
    }
}


Function Restore-pfSenseUserCert {
    <#
            Un-Revoke: Remove a user's certificate from a CRL
    #>
    
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $true, Position = 1,
            HelpMessage = 'User name'
        )] [String] $UserName
    )
    
    Begin {
        
    }
    
    Process {
        
    }
    
    End {
    
    }
}


#endregion

#region System functions


Function Backup-pfSenseConfig {
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
    Param
    (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )]
        [PSObject] $Session,
        
        [Parameter(Position = 1)]
        [Switch] $OutputXML,
        
        [Parameter(Position = 1)]
        [ValidateScript({
                try {
                    $Folder = Get-Item $($_ | Split-Path -Parent) -ErrorAction Stop
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    Throw [System.Management.Automation.ItemNotFoundException] "${_} Maybe there are network issues?"
                }
                if ($Folder.PSIsContainer) {
                    $True
                }
                else {
                    Throw [System.Management.Automation.ValidationMetadataException] "Invalid path '${_}'."
                }
            })]
        [String] $FilePath = ('{0}\{1}_pfSenseBackup.xml' -f $($PWD.Path), $(Get-Date -UFormat '%Y%m%d_%H%M%S')),
        
        [Parameter(Position = 2, ParameterSetName = 'ToDisk')]
        [String] $EncryptPassword
    )
    
    Begin {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process {
        # Variables
        $Server = $Session.host
        [bool] $NoTLS = $Session.NoTLS 
        [Microsoft.PowerShell.Commands.WebRequestSession] $webSession = $Session[0]
        $uri = 'https://{0}/diag_backup.php' -f $Server
    
        If ($NoTLS) { # highway to tha Danger Zone!!!
            $uri = $uri -Replace "^https:", 'http:'
            Invoke-DebugIt -Console -Message '[WARNING]' -Value 'Insecure option selected (no TLS)' -Color 'Yellow'
        }
    
        Invoke-DebugIt -Console -Message '[INFO]' -Value $uri.ToString()
    
        # pfSense requires a lot of magic.... ++ foreach POST 
        $request = Invoke-WebRequest -Uri $uri -Method Get -WebSession $webSession
    
    
        $dictPostData = @{
            __csrf_magic   = $($request.InputFields[0].Value)
            donotbackuprrd = 'yes'
            download       = 'Download configuration as XML'
        }
        
        If ($EncryptPassword) {
            $dictSecurity = @{
                encrypt_password         = "$EncryptPassword" 
                encrypt_password_confirm = "$EncryptPassword"
                encrypt                  = "yes"
            }
        
            $dictPostData += $dictSecurity
        
            Invoke-DebugIt -Console -Message '[INFO]' -Value 'Encryption password set'
        }
    
        Try {
            $rawRequest = Invoke-WebRequest -Uri $uri -Method Post -Body $dictPostData -WebSession $webSession -EA Stop
        }
        
        Catch {
            Write-Error -Message 'Something went wrong submitting the form'
        }
    
        If ($rawRequest) {
            If ($OutputXML) {
                $Encoder = [System.Text.Encoding]::ASCII
                $retVal = $Encoder.GetString($rawRequest.Content)
                
                $retVal
            }
            Else {
                Invoke-DebugIt -Console -Message '[INFO]' -Value ('Output file: {0}' -f $FilePath)
                ConvertFrom-HexToFile -HexString $rawRequest.Content -FilePath $FilePath
            }
        }
    
        Else {
            Write-Error -Message 'Failed to read the output file'
        }
    }
    
    End {
        
    }
}


Function Restore-pfSenseConfig {

}


Function Add-pfSenseStaticRoute {
    
}


Function Get-pfSenseStaticRoute {

}


Function Remove-pfSenseStaticRoute {
    
}


Function Add-pfSenseGateway {
    
}


Function Get-pfSenseGateway {
    
}


Function Remove-pfSenseGateway {
    
}


Function Get-pfSenseCa {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $false, Position = 1,
            HelpMessage = 'CA name or ID'
        )] [String] $Name
    )
    
    Begin {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process {
        # Variables
        $errorActionSilent = 'SilentlyContinue'
        $objOfHolding = @()

        
        # Export the server config to XML object
        [xml] $objXmlFile = Backup-pfSenseConfig -Session $Session -OutputXML 
        $objXmlCrl = $objXmlFile.pfsense.crl
        
        
        # Don't want the cert info to be displayed by default... too messy.
        [String[]] $defaultDisplaySet = 'CA', 'CA_ID', 'Serial', 'CRL'
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(
            'DefaultDisplayPropertySet', [string[]]$defaultDisplaySet
        )
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)

        
        # Iterate thru the CAs and return their infos...
        Foreach ($objCA in $objXmlFile.pfsense.ca) {
            $objBuilder = New-Object -TypeName PSObject
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'CA' -Value $objCA.descr.'#cdata-section'
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'CA_ID' -Value $objCA.refid
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Cert' -Value $objCA.crt
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Key' -Value $objCA.prv
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Serial' -Value $objCA.serial
            
            $crl = $objXmlCrl | Where-Object { $_.caref -eq $objCA.refid }
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'CRL' -Value $crl.descr.'#cdata-section'
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'CRL_ID' -Value $crl.refid
            
            
            $objBuilder.PSObject.TypeNames.Insert(0, 'CA Information')
            $objBuilder | Add-Member -MemberType MemberSet PSStandardMembers $PSStandardMembers
            
            # Add the builder object to our array object
            $objOfHolding += $objBuilder
        }
        
        # Returning data... we're done with the work now
        If ($Name) {
            $objOfHolding | ? { $_.CA -eq $Name -or $_.CA_ID -eq $Name }
        }
        Else {
            $objOfHolding
        }
        
        # Clean up
        Remove-Variable objXmlFile -Force -ErrorAction $errorActionSilent -WarningAction $errorActionSilent
    }
    
    End {
        [GC]::Collect()
    }
}


Function Export-pfSenseCa {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $True, Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $True, Position = 1,
            HelpMessage = 'CA name or ID'
        )] [String] $Name,
        
        [Parameter(Position = 2)]
        [ValidateScript({
                try {
                    $Folder = Get-Item $($_ | Split-Path -Parent) -ErrorAction Stop
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    Throw [System.Management.Automation.ItemNotFoundException] "${_} Maybe there are network issues?"
                }
                if ($Folder.PSIsContainer) {
                    $True
                }
                else {
                    Throw [System.Management.Automation.ValidationMetadataException] "Invalid path '${_}'."
                }
            })]
        [String] $FilePath = ('{0}\pfSenseCA.cer' -f $($PWD.Path))
    )
    
    Try {
        $CA = Get-pfSenseCa -Session $Session -Name $Name 
        
        $Cert = ConvertFrom-Base64 -InputString $CA.Cert
        
        $Cert | Out-File -Encoding ascii -FilePath $FilePath
    }
    Catch {
        Write-Error -Message ('CA {0} not found!' -f $Name)
    }
}


Function Export-pfSenseCrl {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $True, Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $True, Position = 1,
            HelpMessage = 'CRL name or ID'
        )] [String] $Name,
        
        [Parameter(Position = 2)]
        [ValidateScript({
                try {
                    $Folder = Get-Item $($_ | Split-Path -Parent) -ErrorAction Stop
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    Throw [System.Management.Automation.ItemNotFoundException] "${_} Maybe there are network issues?"
                }
                if ($Folder.PSIsContainer) {
                    $True
                }
                else {
                    Throw [System.Management.Automation.ValidationMetadataException] "Invalid path '${_}'."
                }
            })]
        [String] $FilePath = ('{0}\pfSenseCA.crl' -f $($PWD.Path))
    )
    
    Try {
        $CRL = Get-pfSenseCrl -Session $Session -Name $Name 
        
        $Cert = ConvertFrom-Base64 -InputString $CRL.Data
        
        $Cert | Out-File -Encoding ascii -FilePath $FilePath
    }
    Catch {
        Write-Error -Message ('CRL {0} not found!' -f $Name)
    }
}


Function Get-pfSenseCrl {
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0,
            HelpMessage = 'Valid/active websession to server'
        )] [PSObject] $Session,
        
        [Parameter(Mandatory = $false, Position = 1,
            HelpMessage = 'CRL name or ID'
        )] [String] $Name
    )
    
    Begin {
        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
    }
    
    Process {
        # Variables
        $errorActionSilent = 'SilentlyContinue'
        $objOfHolding = @()
        
        # Export the server config to XML object
        [xml] $objXmlFile = Backup-pfSenseConfig -Session $Session -OutputXML 
        $objXmlCa = $objXmlFile.pfsense.ca
        
        # Don't want the cert info to be displayed by default... too messy.
        [String[]] $defaultDisplaySet = 'CRL', 'CRL_ID', 'Method', 'CA'
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(
            'DefaultDisplayPropertySet', [string[]]$defaultDisplaySet
        )
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)

        
        # Iterate thru the CAs and return their infos...
        Foreach ($objCRL in $objXmlFile.pfsense.crl) {
            $objBuilder = New-Object -TypeName PSObject
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'CRL' -Value $objCRL.descr.'#cdata-section'
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'CRL_ID' -Value $objCRL.refid
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Data' -Value $objCRL.text.'#cdata-section'
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Serial' -Value $objCRL.serial
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'LifeTime' -Value $objCRL.lifetime
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'Method' -Value $objCRL.method
            
            $ca = $objXmlCa | Where-Object { $_.refid -eq $objCRL.caref }
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'CA' -Value $ca.descr.'#cdata-section'
            
            $objBuilder | 
            Add-Member -MemberType NoteProperty -Name 'CA_ID' -Value $ca.refid
            
            $objBuilder.PSObject.TypeNames.Insert(0, 'CRL Information')
            $objBuilder | Add-Member -MemberType MemberSet PSStandardMembers $PSStandardMembers
            
            # Add the builder object to our array object
            $objOfHolding += $objBuilder
        }
        
        # Returning data... we're done with the work now
        If ($Name) {
            $objOfHolding | ? { $_.CRL -eq $Name -or $_.CRL_ID -eq $Name }
        }
        Else {
            $objOfHolding
        }
        
        # Clean up
        Remove-Variable objXmlFile -Force -ErrorAction $errorActionSilent -WarningAction $errorActionSilent
    }
    
    End {
        [GC]::Collect()
    }
}


#endregion

#region Firewall functions


Function Add-pfSenseFirewallRule {
    
}


Function Get-pfSenseFirewallRule {
}


Function Remove-pfSenseFirewallRule {
    
}


Function Add-pfSenseNatRule {

}


Function Get-pfSenseNatRule {
}


Function Remove-pfSenseNatRule {
    
}


#endregion

#region Snort functions





#endregion