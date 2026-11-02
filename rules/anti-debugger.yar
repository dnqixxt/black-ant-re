rule Anti_Debugging_Techniques {
    meta:
        author = "Eduardo"
        description = "Detects common Windows user-mode anti-debugging APIs and PEB inspection"
        severity = "Medium"
        mitre_tactic = "Defense Evasion (TA0005) - Execution Guardrails (T1480)"

    strings:
        $api1 = "IsDebuggerPresent" ascii wide
        $api2 = "CheckRemoteDebuggerPresent" ascii wide
        $api3 = "OutputDebugStringA" ascii wide
        $api4 = "OutputDebugStringW" ascii wide
        $api5 = "NtQueryInformationProcess" ascii wide
        $api6 = "ZwQueryInformationProcess" ascii wide

    condition:
        2 of ($api*)
}
