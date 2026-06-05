# Triage-Force - Find Evil Hackathon

Repository for the Triage-Force team participating in the Find Evil Hackathon. 

This repository contains setup scripts and documentation to connect the Antigravity/Cursor AI agent with your SIFT Workstation VM for automated triage, forensic analysis, and evidence gathering.

---

## 🛠️ Environment Configuration

To allow the AI agent to connect to the SIFT Workstation and run forensic tools, we use an **SSH MCP (Model Context Protocol) Server**.

### Connection Details
*   **Target IP:** `192.168.255.128`
*   **SSH Port:** `22`
*   **Username:** `sansforensics`
*   **Password:** `forensics`

---

## 🚀 Getting Started

### 1. Automatically Configure the SSH MCP Server
Run the PowerShell script included in this repository to automatically write the SIFT Workstation configuration into your IDE settings (`~/.gemini/config/mcp_config.json`):

```powershell
# Run this from the repository root
.\setup-mcp.ps1
```

### 2. Manual Configuration
If you prefer to configure it manually, add the following object to the `mcpServers` section of your `~/.gemini/config/mcp_config.json` file:

```json
{
  "mcpServers": {
    "sift-workstation": {
      "command": "npx",
      "args": [
        "-y",
        "@fangjunjie/ssh-mcp-server",
        "--host", "192.168.255.128",
        "--port", "22",
        "--username", "sansforensics",
        "--password", "forensics"
      ]
    }
  }
}
```

---

## 🔍 Verifying the Connection
Once configured, reload the IDE or agent panel. The `sift-workstation` MCP server will start up, allowing you to run terminal commands, view files, and triage artifacts on the SIFT VM directly through the AI agent interface.
