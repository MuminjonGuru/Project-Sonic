param(
    [Parameter(Mandatory = $true)]
    [string]$ReportDirectory,
    [string]$CompareWith
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$workspace = Join-Path $root 'workspace'
$report = [IO.Path]::GetFullPath($ReportDirectory, $root)
if (-not $report.StartsWith($workspace + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'ReportDirectory must be a new directory inside the development workspace.'
}
if (Test-Path -LiteralPath $report) {
    throw 'Refusing to overwrite a previous verification directory.'
}
$before = if ($CompareWith) {
    @(Get-Content -LiteralPath $CompareWith -Raw | ConvertFrom-Json)
} else { @() }
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Run this PowerShell helper from the provisioned Windows environment.'
}
$cases = @(
    @{ tool = 'semgrep'; case = 'semgrep-basic'; state = 'complete'; exit = 0 },
    @{ tool = 'kics'; case = 'kics-basic'; state = 'complete'; exit = 0 },
    @{ tool = 'kics'; case = 'kics-clean'; state = 'complete'; exit = 0 },
    @{ tool = 'kics'; case = 'kics-malformed'; state = 'partial'; exit = 8 },
    @{ tool = 'kics'; case = 'kics-unsupported'; state = 'complete'; exit = 0 }
)
New-Item -ItemType Directory -Path $report | Out-Null
$records = @()
Push-Location -LiteralPath $root
try {
    foreach ($case in $cases) {
        $target = Join-Path $root ('test_cases\development\' + $case.case + '\target')
        $runWorkspace = Join-Path $report 'runs-workspace'
        $output = & $python -m agentsec_evidence scan $case.tool $target `
            --label ('fixture:' + $case.case) --revision fixture-v1 `
            --run-label ('orchestration-regression-' + $case.case) `
            --source-kind project-fixture --license-status project-authored-private `
            --workspace $runWorkspace --json 2> (Join-Path $report ($case.case + '-stderr.txt'))
        $code = $LASTEXITCODE
        $output | Set-Content -LiteralPath (Join-Path $report ($case.case + '-stdout.json')) -Encoding utf8
        $result = ($output -join "`n") | ConvertFrom-Json
        $equal = $null
        if ($CompareWith) {
            $prior = @($before | Where-Object case -EQ $case.case)
            if ($prior.Count -ne 1) { throw "Expected one baseline for $($case.case)." }
            $equal = $prior[0].result.semantic_sha256 -eq $result.semantic_sha256
        }
        $records += [pscustomobject]@{
            case = $case.case
            exit = $code
            expected_exit = $case.exit
            semantic_matches_before = $equal
            result = $result
        }
        $records | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $report 'results.json') -Encoding utf8
        if ($code -ne $case.exit -or $result.terminal_state -ne $case.state -or $equal -eq $false) {
            throw "Regression for $($case.case): exit=$code; state=$($result.terminal_state); semantic_equal=$equal"
        }
        $validation = & $python -m agentsec_evidence validate $result.run_id --workspace $runWorkspace --json
        $validationCode = $LASTEXITCODE
        $validation | Set-Content -LiteralPath (Join-Path $report ($case.case + '-validation.json')) -Encoding utf8
        if ($validationCode -ne 0) { throw "Bundle validation failed for $($case.case)." }
        Write-Output "$($case.case): $($result.terminal_state); semantic=$($result.semantic_sha256)"
    }
}
finally {
    Pop-Location
}
