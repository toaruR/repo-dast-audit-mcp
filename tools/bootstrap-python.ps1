[CmdletBinding()]
param(
    [switch]$Create,
    [string]$PythonPath = 'C:\Users\toaru\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
)

$ErrorActionPreference = 'Stop'

$requiredPython = 'C:\Users\toaru\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$requiredFullPath = [IO.Path]::GetFullPath($requiredPython)
$requestedFullPath = [IO.Path]::GetFullPath($PythonPath)

if ($requestedFullPath -ne $requiredFullPath) {
    throw "PythonPath must be the bundled CPython 3.12 runtime: $requiredPython"
}
if (-not (Test-Path -LiteralPath $requiredFullPath -PathType Leaf)) {
    throw "Required bundled CPython 3.12 runtime is unavailable: $requiredPython"
}

$probe = & $requiredFullPath -c "import platform, sys; print(f'{platform.python_implementation()}|{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or $probe.Trim() -ne 'CPython|3.12') {
    throw "Required runtime must report CPython 3.12; got '$probe'."
}
if (-not $Create) {
    throw 'Pass -Create to create or verify the local .venv.'
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$venvDir = Join-Path $repositoryRoot '.venv'
$venvPython = Join-Path $venvDir 'Scripts\python.exe'

if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    & $requiredFullPath -m venv $venvDir
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to create .venv with the required bundled CPython 3.12 runtime.'
    }
}

$venvProbe = & $venvPython -c "import platform, sys; print(f'{platform.python_implementation()}|{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or $venvProbe.Trim() -ne 'CPython|3.12') {
    throw "Local .venv is not CPython 3.12; got '$venvProbe'. Remove .venv manually, then rerun this script."
}

# CPython 3.12's ensurepip intentionally omits setuptools.  Avoid downloading
# a build dependency or using global site-packages: a local .pth installs this
# stdlib-only source package into this venv for development and test execution.
$sitePackages = & $venvPython -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $sitePackages -PathType Container)) {
    throw 'Failed to locate the local .venv site-packages directory.'
}
$pthPath = Join-Path $sitePackages 'repo_dast_audit_mcp.pth'
$sourcePath = Join-Path $repositoryRoot 'src'
Set-Content -LiteralPath $pthPath -Value $sourcePath -Encoding ascii

& $venvPython -c "import repo_dast_audit_mcp; print(repo_dast_audit_mcp.__version__)"
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to install the local package into .venv.'
}
