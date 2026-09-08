<#
=======================================================================
 check-windows.ps1 — Verification automatique du TP2 (Windows / AD)
 Fourni AUX ETUDIANTS des le lancement du TP : le bareme est public.
 A executer en administrateur sur la VM durcie.
=======================================================================
#>
#Requires -RunAsAdministrator

$script:Pass = 0; $script:Total = 0
function Chk([string]$Label, [scriptblock]$Test) {
    $script:Total++
    $r = $false
    try { $r = [bool](& $Test) } catch { $r = $false }
    if ($r) { Write-Host "  [PASS] $Label" -Foreground Green; $script:Pass++ }
    else    { Write-Host "  [FAIL] $Label" -Foreground Red }
}
function Sec([string]$t) { Write-Host ""; Write-Host "=== $t ===" -Foreground Cyan }
function RegVal($p,$n) { try { (Get-ItemProperty $p -Name $n -ErrorAction Stop).$n } catch { $null } }

Sec "A. SERVICE METIER (eliminatoire)"
$metier = $false
try {
    $r = Invoke-WebRequest "http://127.0.0.1:8080/health.txt" -UseBasicParsing -TimeoutSec 5
    if ($r.Content -match "OK") { $metier = $true }
} catch {}
if ($metier) { Write-Host "  [PASS] Service metier accessible sur 8080" -Foreground Green }
else { Write-Host "  [FAIL] SERVICE METIER HS -> note plafonnee a 08/20" -Foreground Red }

Sec "B. COMPTES LOCAUX"
Chk "Compte Invite/Guest desactive" { -not ((Get-LocalUser | Where-Object {$_.Name -in @('Invite','Guest')}).Enabled -contains $true) }
Chk "Compte stagiaire supprime ou desactive" { $u=Get-LocalUser -Name stagiaire -EA SilentlyContinue; (-not $u) -or (-not $u.Enabled) }
Chk "Groupe Administrateurs reduit (<= 2 membres)" { @(Get-LocalGroupMember -Group (Get-LocalGroup | ? {$_.SID -like 'S-1-5-32-544'}).Name).Count -le 2 }
Chk "Aucun compte avec mot de passe sans expiration (hors integres)" { @(Get-LocalUser | ? {$_.Enabled -and $_.PasswordNeverExpires -and $_.Name -notmatch 'DefaultAccount|WDAG'}).Count -eq 0 }
Chk "Longueur minimale de mot de passe >= 14" { (net accounts) -match 'minimum.*: *(1[4-9]|[2-9][0-9])' }
Chk "Verrouillage de compte actif (seuil entre 1 et 10)" { (net accounts) -match 'seuil|Lockout threshold' -and (net accounts | Select-String 'seuil|threshold') -notmatch 'Jamais|Never' }

Sec "C. UAC"
$sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Chk "EnableLUA = 1" { (RegVal $sys EnableLUA) -eq 1 }
Chk "ConsentPromptBehaviorAdmin >= 2" { (RegVal $sys ConsentPromptBehaviorAdmin) -ge 2 }
Chk "PromptOnSecureDesktop = 1" { (RegVal $sys PromptOnSecureDesktop) -eq 1 }
Chk "LocalAccountTokenFilterPolicy = 0 ou absent" { $v=RegVal $sys LocalAccountTokenFilterPolicy; ($null -eq $v) -or ($v -eq 0) }

Sec "D. DEFENDER ET ASR"
Chk "Protection temps reel active" { -not (Get-MpPreference).DisableRealtimeMonitoring }
Chk "Protection PUA activee" { (Get-MpPreference).PUAProtection -ge 1 }
Chk "Cloud protection activee" { (Get-MpPreference).MAPSReporting -ge 1 }
Chk "Au moins 5 regles ASR configurees" { @((Get-MpPreference).AttackSurfaceReductionRules_Ids).Count -ge 5 }
Chk "Signatures de moins de 7 jours" { ((Get-Date) - (Get-MpComputerStatus).AntivirusSignatureLastUpdated).Days -le 7 }

Sec "E. PROTOCOLES ET PARTAGES"
Chk "SMBv1 desactive" { -not (Get-SmbServerConfiguration).EnableSMB1Protocol }
Chk "Signature SMB exigee" { (Get-SmbServerConfiguration).RequireSecuritySignature }
Chk "Partage Public supprime ou restreint" { $s=Get-SmbShare -Name Public -EA SilentlyContinue; (-not $s) -or (-not (Get-SmbShareAccess Public | ? {$_.AccountName -match 'Everyone|Tout le monde' -and $_.AccessRight -eq 'Full'})) }
$lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Chk "LmCompatibilityLevel = 5" { (RegVal $lsa LmCompatibilityLevel) -eq 5 }
Chk "RestrictAnonymous = 1" { (RegVal $lsa RestrictAnonymous) -ge 1 }
Chk "LSA Protection (RunAsPPL) = 1" { (RegVal $lsa RunAsPPL) -eq 1 }
Chk "WDigest ne stocke pas les mots de passe en clair" { $v=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential; ($null -eq $v) -or ($v -eq 0) }

Sec "F. RDP"
Chk "RDP desactive OU NLA exige" { ((RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" fDenyTSConnections) -eq 1) -or ((RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" UserAuthentication) -eq 1) }

Sec "G. PARE-FEU"
Chk "Pare-feu actif sur les 3 profils" { @(Get-NetFirewallProfile | ? {-not $_.Enabled}).Count -eq 0 }
Chk "Trafic entrant bloque par defaut" { @(Get-NetFirewallProfile | ? {$_.DefaultInboundAction -ne 'Block'}).Count -eq 0 }

Sec "H. POWERSHELL ET EXECUTION"
Chk "ExecutionPolicy machine != Bypass/Unrestricted" { (Get-ExecutionPolicy -Scope LocalMachine) -notin @('Bypass','Unrestricted') }
Chk "ScriptBlockLogging active" { (RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" EnableScriptBlockLogging) -eq 1 }
Chk "PowerShell v2 desactive" { (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State -ne 'Enabled' }

Sec "I. JOURNALISATION"
Chk "Audit des ouvertures de session (succes et echec)" { (auditpol /get /category:* | Select-String 'Ouverture de session|Logon') -match 'Succes et echec|Success and Failure' }
Chk "Journal Securite >= 128 Mo" { (Get-WinEvent -ListLog Security).MaximumSizeInBytes -ge 134217728 }
Chk "Audit creation de processus active" { (auditpol /get /subcategory:"Creation du processus","Process Creation" | Select-String 'Succes|Success') -ne $null }

Sec "J. TACHES ET PERMISSIONS"
Chk "Tache MaintenanceMetier supprimee ou non-SYSTEM" { $t=Get-ScheduledTask -TaskName MaintenanceMetier -EA SilentlyContinue; (-not $t) -or ($t.Principal.UserId -ne 'SYSTEM') }
Chk "C:\Scripts n'est plus accessible a Tout le monde" { -not ((icacls C:\Scripts 2>$null) -match 'Everyone:\(|Tout le monde:\(') }

Sec "K. MISES A JOUR"
Chk "Mises a jour automatiques reactivees" { $v=RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" NoAutoUpdate; ($null -eq $v) -or ($v -eq 0) }

Write-Host ""
Write-Host "======================================================"
Write-Host " Controles reussis : $script:Pass / $script:Total"
$score = [math]::Floor($script:Pass * 60 / $script:Total)
Write-Host " Score technique   : $score / 60"
if (-not $metier) { Write-Host " ATTENTION : service metier HS -> note plafonnee a 08/20" -Foreground Red }
Write-Host "======================================================"
