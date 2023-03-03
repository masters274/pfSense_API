$modulePath = "$PSScriptRoot\pfSense"

$manifest = Import-PowerShellDataFile -Path "$modulePath\*.psd1"

$requiredModules = $manifest.RequiredModules.ModuleName

if ($requiredModules) { # Test-ModuleManifest will fail if RequiredModules are not on the deployment machine
    foreach ($mod in $requiredModules) {
        $module = Get-Module -Name $mod -ListAvailable
        if ($null -eq $module) {
            Install-Module -Name $mod -Force -Scope CurrentUser
        }
    }
}

Publish-Module -Path $modulePath -NuGetApiKey $Env:APIKEY