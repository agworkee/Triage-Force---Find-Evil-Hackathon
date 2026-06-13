# setup-mcp.ps1
# Script to configure the SSH MCP server connection to the SIFT Workstation.

$ConfigDir = "$Home\.gemini\config"
$ConfigFile = "$ConfigDir\mcp_config.json"

# Create config directory if it doesn't exist
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

$SiftConfig = @{
    command = "ssh"
    args = @(
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "sansforensics@192.168.255.128",
        "sudo",
        "/opt/triageforce/venv/bin/python",
        "/opt/triageforce/server.py"
    )
}

if (Test-Path $ConfigFile) {
    try {
        $Content = Get-Content $ConfigFile -Raw
        $CurrentConfig = $Content | ConvertFrom-Json
        
        if ($null -eq $CurrentConfig) {
            $CurrentConfig = [pscustomobject]@{ mcpServers = [pscustomobject]@{} }
        }
        
        if (-not (Get-Member -InputObject $CurrentConfig -Name "mcpServers")) {
            $CurrentConfig | Add-Member -MemberType NoteProperty -Name "mcpServers" -Value ([pscustomobject]@{})
        }
        
        # Add or update the triageforce config
        $CurrentConfig.mcpServers | Add-Member -MemberType NoteProperty -Name "triageforce" -Value $SiftConfig -Force
        
        $JsonConfig = $CurrentConfig | ConvertTo-Json -Depth 100
        $JsonConfig | Out-File -FilePath $ConfigFile -Encoding utf8 -Force
        Write-Host "Updated existing MCP config at: $ConfigFile"
    } catch {
        Write-Warning "Could not parse existing mcp_config.json. Creating a backup and overwriting."
        Copy-Item -Path $ConfigFile -Destination "$ConfigFile.bak" -Force
        $NewConfig = [pscustomobject]@{ mcpServers = [pscustomobject]@{ "triageforce" = $SiftConfig } }
        $NewConfig | ConvertTo-Json -Depth 100 | Out-File -FilePath $ConfigFile -Encoding utf8 -Force
        Write-Host "Created new MCP config at: $ConfigFile (Backup saved as $ConfigFile.bak)"
    }
} else {
    $NewConfig = [pscustomobject]@{ mcpServers = [pscustomobject]@{ "triageforce" = $SiftConfig } }
    $NewConfig | ConvertTo-Json -Depth 100 | Out-File -FilePath $ConfigFile -Encoding utf8 -Force
    Write-Host "Created new MCP config at: $ConfigFile"
}

Write-Host "SSH MCP Server configured successfully for SIFT Workstation (192.168.255.128)."
