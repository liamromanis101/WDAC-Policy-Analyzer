param(
    [Parameter(Mandatory=$true)]
    [string]$PolicyXml
)

"Starting WDAC Runtime Assessment"

if (!(Test-Path $PolicyXml)) {
    "Policy XML not found"
    exit 1
}

[xml]$policy = Get-Content $PolicyXml

# ============================================================
# Active WDAC detection (non-admin)
# ============================================================

""
"--- Active WDAC Detection ---"

$found = $false

try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 20 |
              Where-Object { $_.Id -eq 3099 }

    foreach ($e in $events) {
        "Policy Load Event: " + $e.TimeCreated
        $found = $true
    }
}
catch {}

if (!$found) {
    "No WDAC policy load events detected."
}

"NOTE: Run 'citool -lp' as Administrator to enumerate active policies."
"--- End Active WDAC Detection ---"
""

# ============================================================
# WDAC Policy Options (XML)
# ============================================================

"--- WDAC Policy Option Assessment (XML) ---"

$options = $policy.SiPolicy.PolicyRuleOptions.Option | ForEach-Object { $_.OptionId }
function HasOpt($id) { return $options -contains $id }

if (HasOpt 10) { "CRITICAL: Unsigned System Integrity Policy ENABLED" }
if (HasOpt 7)  { "CRITICAL: Test Signing ENABLED" }
if (HasOpt 8)  { "CRITICAL: Debug Mode ENABLED" }
if (HasOpt 4)  { "CRITICAL: Advanced Boot Options Menu ENABLED" }

if (!(HasOpt 6)) { "CRITICAL: UMCI NOT enabled" }
if (HasOpt 3)    { "WARNING: Policy is in AUDIT MODE" }

if (!(HasOpt 5)) { "WARNING: Boot Menu Protection NOT enabled" }
if (!(HasOpt 9)) { "INFO: Intelligent Security Graph not enabled" }
if (!(HasOpt 13)){ "INFO: Managed Installer not enabled" }

"--- End WDAC Policy Option Assessment ---"
""

# ============================================================
# Registry WDAC posture
# ============================================================

"--- WDAC Registry Posture ---"

try {
    $ci = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI" -ErrorAction Stop

    if ($ci.Enabled -eq 1) { "WDAC Enabled (registry): Yes" } else { "WDAC Enabled (registry): No" }
    if ($ci.UMCIEnabled -eq 1) { "UMCI Enabled (registry): Yes" } else { "UMCI Enabled (registry): No" }

    if ($ci.DebugFlags -ne 0) { "CRITICAL: DebugFlags set: $($ci.DebugFlags)" }
    if ($ci.TestFlags -ne 0)  { "CRITICAL: TestFlags set: $($ci.TestFlags)" }
}
catch {
    "Unable to read CI registry keys."
}

"--- End WDAC Registry Posture ---"
""

# ============================================================
# Security Controls Status (correct WDAC checks)
# ============================================================

$ciLogExists = $false
try {
    Get-WinEvent -ListLog "Microsoft-Windows-CodeIntegrity/Operational" -ErrorAction Stop | Out-Null
    $ciLogExists = $true
}
catch {}

$ciBlocks = 0
$lastBlock = $null
try {
    $blocks = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 50 |
              Where-Object { $_.Id -eq 3076 }

    $ciBlocks = $blocks.Count
    if ($ciBlocks -gt 0) { $lastBlock = ($blocks | Select-Object -First 1).TimeCreated }
}
catch {}

"WDAC Log Present: $ciLogExists"
"Recent WDAC Blocks (3076): $ciBlocks"
if ($lastBlock) { "Most Recent WDAC Block: $lastBlock" }

if (!$ciLogExists) { "WARNING: Code Integrity log missing — WDAC may not be present." }
if ($ciBlocks -eq 0) { "WARNING: No WDAC blocks observed — policy may be permissive." }

$appLocker = Get-Service AppIDSvc -ErrorAction SilentlyContinue
$defender = Get-Service WinDefend -ErrorAction SilentlyContinue

"AppLocker Service : " + ($(if($appLocker){$appLocker.Status}else{"Not Present"}))
"Defender Service  : " + ($(if($defender){$defender.Status}else{"Not Present"}))
""

# ============================================================
# Runtime setup
# ============================================================

$Temp = "$env:TEMP\wdac_tests"
New-Item -ItemType Directory -Force -Path $Temp | Out-Null

$WdacPublishers = @()
try { $WdacPublishers = $policy.SiPolicy.Signers.Signer.CertPublisher } catch {}

$Report = @()

function AddRow {
    param(
        $RuleID,$RuleType,$RuleValue,$Binary,$Exists,
        $WDACDecision,$ExecutionOutcome,
        $Publisher,$IdentityEnforced,$Severity,$Notes
    )

    $script:Report += New-Object psobject -Property @{
        RuleID = $RuleID
        RuleType = $RuleType
        RuleValue = $RuleValue
        ResolvedBinary = $Binary
        ExistsOnSystem = $Exists
        WDACDecision = $WDACDecision
        ExecutionOutcome = $ExecutionOutcome
        Publisher = $Publisher
        IdentityEnforced = $IdentityEnforced
        Severity = $Severity
        Notes = $Notes
    }
}

function Get-ExecutionOutcome {

    $timeout = (Get-Date).AddSeconds(3)

    while ((Get-Date) -lt $timeout) {

        # WDAC
        if (Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 5 |
            Where-Object { $_.Id -eq 3076 }) {
            return "BlockedByWDAC"
        }

        # AppLocker
        if (Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 5 -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -eq 8004 }) {
            return "BlockedByAppLocker"
        }

        # Defender
        if (Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -in 1116,1121 }) {
            return "BlockedByDefender"
        }

        Start-Sleep -Milliseconds 300
    }

    return "UnknownBlock"
}


function RateSeverity($RuleType,$WDACDecision,$Identity,$Exists) {

    if ($Exists -ne "Yes") { return "Info" }

    if ($RuleType -eq "Deny" -and $WDACDecision -eq "AllowedByWDAC") { return "Critical" }
    if ($Identity -eq "Unsigned" -and $WDACDecision -eq "AllowedByWDAC") { return "Critical" }
    if ($Identity -eq "No" -and $WDACDecision -eq "AllowedByWDAC") { return "High" }
    if ($WDACDecision -eq "NotBlockedByWDAC") { return "Low" }
    if ($WDACDecision -eq "BlockedByWDAC") { return "Info" }

    return "Info"
}

function ProcessRule {
    param($Rule,$RuleType)

    $ruleId = $Rule.ID

    if ($Rule.FilePath) { $value = $Rule.FilePath }
    elseif ($Rule.FileName) { $value = $Rule.FileName }
    elseif ($Rule.FriendlyName) { $value = $Rule.FriendlyName }
    else { $value = "[Unresolvable rule]" }

    "Processing $RuleType rule: $value"

    $resolved=""
    $exists="No"
    $publisher=""
    $identity=""

    if ($Rule.FilePath -and (Test-Path $Rule.FilePath)) {
        $resolved=$Rule.FilePath; $exists="Yes"
    }

    if (!$resolved -and $Rule.FileName) {
        $f=Get-ChildItem "C:\Program Files","C:\Windows\System32" -Recurse -Filter $Rule.FileName -ErrorAction SilentlyContinue | Select -First 1
        if ($f){$resolved=$f.FullName;$exists="Yes"}
    }

    if ($exists -eq "Yes") {
        try {
            $sig=Get-AuthenticodeSignature $resolved
            if ($sig.SignerCertificate) {
                $publisher=$sig.SignerCertificate.Subject
                if ($WdacPublishers -match $publisher){$identity="Yes"} else {$identity="No"}
            } else {
                $publisher="Unsigned";$identity="Unsigned"
            }
        } catch {$publisher="Unknown";$identity="Unknown"}
    }

    $sev = RateSeverity $RuleType "" $identity $exists
    $note=""
    if ($exists -ne "Yes") { $note="Rule target not present on system" }

    AddRow $ruleId $RuleType $value $resolved $exists "" "" $publisher $identity $sev $note

    if ($exists -ne "Yes") { return }

    $dest=Join-Path $Temp "renamed.exe"
    Copy-Item $resolved $dest -Force

    try {
        Start-Process $dest -WindowStyle Hidden
        Start-Sleep 2
        $ExecutionOutcome="Allowed"
        $WDACDecision="AllowedByWDAC"
    }
    catch {
        $ExecutionOutcome=Get-ExecutionOutcome
        if ($ExecutionOutcome -eq "BlockedByWDAC") {
            $WDACDecision="BlockedByWDAC"
        } else {
            $WDACDecision="NotBlockedByWDAC"
        }
    }

    $sev=RateSeverity $RuleType $WDACDecision $identity "Yes"

    AddRow $ruleId $RuleType $value $resolved "Yes" $WDACDecision $ExecutionOutcome $publisher $identity $sev ""

    Remove-Item $dest -Force -ErrorAction SilentlyContinue
}

foreach ($a in $policy.SiPolicy.FileRules.Allow) { ProcessRule $a "Allow" }
foreach ($d in $policy.SiPolicy.FileRules.Deny)  { ProcessRule $d "Deny" }

# ============================================================
# CSV + Summary
# ============================================================

$Report | Export-Csv ".\WDAC_Runtime_Assessment.csv" -NoTypeInformation

""
"--- Summary ---"

$total = $Report.Count

$allowedByWDAC   = ($Report | Where-Object { $_.WDACDecision -eq "AllowedByWDAC" }).Count
$notBlockedWDAC  = ($Report | Where-Object { $_.WDACDecision -eq "NotBlockedByWDAC" }).Count
$blockedByWDAC   = ($Report | Where-Object { $_.WDACDecision -eq "BlockedByWDAC" }).Count

$blockedDefender = ($Report | Where-Object { $_.ExecutionOutcome -eq "BlockedByDefender" }).Count
$blockedAppLocker= ($Report | Where-Object { $_.ExecutionOutcome -eq "BlockedByAppLocker" }).Count
$blockedUnknown  = ($Report | Where-Object { $_.ExecutionOutcome -eq "UnknownBlock" }).Count

$executedUnblocked = ($Report | Where-Object { $_.ExecutionOutcome -eq "Allowed" }).Count

$critical = ($Report | Where-Object { $_.Severity -eq "Critical" }).Count
$high     = ($Report | Where-Object { $_.Severity -eq "High" }).Count

"Total rows: $total"
"AllowedByWDAC: $allowedByWDAC"
"NotBlockedByWDAC: $notBlockedWDAC"
"BlockedByWDAC: $blockedByWDAC"
"BlockedByDefender: $blockedDefender"
"BlockedByAppLocker: $blockedAppLocker"
"BlockedByUnknown: $blockedUnknown"
"ExecutedWithoutAnyBlock: $executedUnblocked"
"Critical findings: $critical"
"High findings: $high"

"--- End Summary ---"
""
"Output: WDAC_Runtime_Assessment.csv"
"Done."
