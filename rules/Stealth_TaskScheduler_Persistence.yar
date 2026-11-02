rule Stealth_TaskScheduler_Persistence {
    meta:
        author = "Eduardo"
        description = "Detects stealth persistence using masqueraded scheduled task names or Startup shortcut tampering"
        severity = "High"
        mitre_tactic = "Persistence (TA0003) - Scheduled Task/Job (T1053)"

    strings:
        // Command syntax
        $sch = "schtasks /create /tn" ascii wide nocase
        $args = "/sc onlogon /delay" ascii wide nocase
        
        // Masqueraded legitimate service names (Defense Evasion)
        $mask1 = "MicrosoftEdgeUpdateTaskMachineUA" ascii wide
        $mask2 = "OneDriveStandaloneUpdater" ascii wide
        $mask3 = "GoogleUpdateTaskMachineUA" ascii wide
        $mask4 = "WindowsSecurityHealthService" ascii wide
        
        // PowerShell shortcut persistence in Startup folder
        $ps_shortcut = "$WScriptShell.CreateShortcut" ascii wide nocase

    condition:
        ($sch and $args and any of ($mask*)) or $ps_shortcut
}
