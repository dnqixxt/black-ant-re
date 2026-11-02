rule LSASS_Impersonation_DPAPI_Stealer {
    meta:
        author = "Eduardo"
        description = "Detects credential dumping via LSASS impersonation (ctypes) and NCrypt provider abuse (App-Bound encryption)"
        severity = "Critical"
        mitre_tactic = "Credential Access (TA0006) - OS Credential Dumping (T1003)"

    strings:
        // Critical Windows token duplication and privilege escalation APIs
        $api1 = "SeDebugPrivilege" ascii wide
        $api2 = "ImpersonateLoggedOnUser" ascii wide
        $api3 = "DuplicateTokenEx" ascii wide
        $api4 = "NCryptOpenStorageProvider" ascii wide
        
        // Artifact-specific logical signatures
        $python_lsass = "impersonate_lsass_ctypes" ascii wide
        $browser_crypt1 = "app_bound_encrypted_key" ascii wide
        $browser_crypt2 = "PK11SDR_Decrypt" ascii wide // Firefox nss3.dll decrypt routine

    condition:
        ($python_lsass) or (3 of ($api*)) or ($browser_crypt1 and $browser_crypt2)
}
