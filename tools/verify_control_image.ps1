Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$image = 'agentsec-evidence-control:0.1.0'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

Push-Location -LiteralPath $root
try {
    & docker build --pull=false --tag $image --file 'containers/control/Dockerfile' .
    if ($LASTEXITCODE -ne 0) {
        throw "Control-image build failed with exit code $LASTEXITCODE"
    }

    $version = & docker run --rm --network none --read-only `
        --tmpfs '/tmp:rw,noexec,nosuid,size=64m' `
        --cap-drop ALL --security-opt no-new-privileges `
        --user '65534:65534' $image version
    if ($LASTEXITCODE -ne 0) {
        throw "Control-image smoke test failed with exit code $LASTEXITCODE"
    }
    if ($version.Trim() -ne '0.1.0') {
        throw "Unexpected control-image version: $version"
    }
    Write-Output "Control image verified: $image ($version)"
}
finally {
    Pop-Location
}
