<#
=======================================================================
 degrade-windows.ps1 — Baseline degradee (TP2)
 Cours : Durcissement Linux et Windows — 5e annee
 Cible : Windows 11 / Windows Server 2022 d'evaluation, en VM isolee.
 A EXECUTER DANS UNE VM DE LABORATOIRE UNIQUEMENT, en administrateur.

 Aucune technique offensive ici : uniquement de la configuration laxiste.
=======================================================================
#>
#Requires -RunAsAdministrator

Write-Host "----------------------------------------------------------" -Foreground Yellow
Write-Host " Ce script degrade volontairement la configuration Windows." -Foreground Yellow
Write-Host " VM de laboratoire isolee uniquement. Jamais sur un vrai poste." -Foreground Yellow
Write-Host "----------------------------------------------------------" -Foreground Yellow
$ok = Read-Host "Taper OUI en majuscules pour continuer"
if ($ok -cne "OUI") { Write-Host "Abandon."; exit 1 }

# --- 1. Service metier a preserver : site IIS sur 8080 ---
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -All -NoRestart | Out-Null
New-Item -Path "C:\metier" -ItemType Directory -Force | Out-Null
"OK" | Out-File "C:\metier\health.txt" -Encoding ascii -NoNewline
@"
<!doctype html><html><head><meta charset="utf-8"><title>Service metier</title></head>
<body><h1>Application metier</h1></body></html>
"@ | Out-File "C:\metier\index.html" -Encoding utf8
Import-Module WebAdministration -ErrorAction SilentlyContinue
if (-not (Get-Website -Name "Metier" -ErrorAction SilentlyContinue)) {
    New-Website -Name "Metier" -Port 8080 -PhysicalPath "C:\metier" -Force | Out-Null
}
Start-Website -Name "Metier" -ErrorAction SilentlyContinue

# --- 2. Comptes locaux laxistes ---
$pw = ConvertTo-SecureString "Password1" -AsPlainText -Force
foreach ($u in @("alice","bob","stagiaire","deploy")) {
    if (-not (Get-LocalUser -Name $u -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $u -Password $pw -PasswordNeverExpires -AccountNeverExpires | Out-Null
    }
}
Add-LocalGroupMember -Group "Administrateurs" -Member "stagiaire","bob" -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Administrators" -Member "stagiaire","bob" -ErrorAction SilentlyContinue
Enable-LocalUser -Name "Invite" -ErrorAction SilentlyContinue
Enable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

# --- 3. Politique de mot de passe et verrouillage inexistantes ---
secedit /export /cfg C:\pol.inf | Out-Null
(Get-Content C:\pol.inf) `
  -replace 'MinimumPasswordLength = \d+','MinimumPasswordLength = 0' `
  -replace 'PasswordComplexity = \d+','PasswordComplexity = 0' `
  -replace 'MaximumPasswordAge = -?\d+','MaximumPasswordAge = -1' `
  -replace 'LockoutBadCount = \d+','LockoutBadCount = 0' | Set-Content C:\pol.inf
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\pol.inf /areas SECURITYPOLICY | Out-Null
Remove-Item C:\pol.inf -Force

# --- 4. Defender et protections affaiblis ---
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue
Set-MpPreference -PUAProtection Disabled -ErrorAction SilentlyContinue
Set-MpPreference -AttackSurfaceReductionRules_Ids @() -AttackSurfaceReductionRules_Actions @() -ErrorAction SilentlyContinue

# --- 5. UAC abaisse ---
$sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty $sys -Name "EnableLUA" -Value 1
Set-ItemProperty $sys -Name "ConsentPromptBehaviorAdmin" -Value 0
Set-ItemProperty $sys -Name "PromptOnSecureDesktop" -Value 0
Set-ItemProperty $sys -Name "LocalAccountTokenFilterPolicy" -Value 1

# --- 6. Protocoles obsoletes et partages ---
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force -ErrorAction SilentlyContinue
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "C:\Partage" -ItemType Directory -Force | Out-Null
New-SmbShare -Name "Public" -Path "C:\Partage" -FullAccess "Tout le monde","Everyone" -ErrorAction SilentlyContinue | Out-Null
$lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty $lsa -Name "LmCompatibilityLevel" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty $lsa -Name "RestrictAnonymous" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty $lsa -Name "RunAsPPL" -Value 0 -ErrorAction SilentlyContinue

# --- 7. RDP ouvert sans NLA ---
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0
Enable-NetFirewallRule -DisplayGroup "Bureau a distance" -ErrorAction SilentlyContinue
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

# --- 8. Pare-feu desactive ---
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# --- 9. Journalisation minimale ---
foreach ($cat in @("Ouverture/Fermeture de session","Logon/Logoff","Suivi detaille","Detailed Tracking","Acces aux objets","Object Access")) {
    auditpol /set /category:"$cat" /success:disable /failure:disable 2>$null | Out-Null
}
wevtutil sl Security /ms:1048576 2>$null

# --- 10. PowerShell sans garde-fous ---
Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
$psl = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $psl -Force | Out-Null
Set-ItemProperty $psl -Name "EnableScriptBlockLogging" -Value 0

# --- 11. Mises a jour automatiques desactivees ---
$au = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
New-Item $au -Force | Out-Null
Set-ItemProperty $au -Name "NoAutoUpdate" -Value 1

# --- 12. Tache planifiee douteuse en SYSTEM, chemin non protege ---
New-Item -Path "C:\Scripts" -ItemType Directory -Force | Out-Null
"Get-Date | Out-File C:\Scripts\last-run.txt" | Out-File "C:\Scripts\maintenance.ps1" -Encoding ascii
icacls "C:\Scripts" /grant "Tout le monde:(OI)(CI)F" 2>$null | Out-Null
icacls "C:\Scripts" /grant "Everyone:(OI)(CI)F"        2>$null | Out-Null
$a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Scripts\maintenance.ps1"
$t = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -TaskName "MaintenanceMetier" -Action $a -Trigger $t -User "SYSTEM" -RunLevel Highest -Force | Out-Null

Write-Host ""
Write-Host "[OK] Baseline degradee installee." -Foreground Green
Write-Host "     Service metier : http://127.0.0.1:8080/health.txt -> doit renvoyer OK"
Write-Host "     Faites un instantane nomme 'baseline' MAINTENANT."
