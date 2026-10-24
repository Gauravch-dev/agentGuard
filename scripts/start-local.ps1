# Local prototype launcher. Secrets exist in this process environment only.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$names = @('AG_OWNER_TOKEN','AG_RUNTIME_TOKEN','AG_INTEGRITY_KEY','AG_DATABASE_PATH')
$previous = @{}
foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name) }
try {
    foreach ($name in @('AG_OWNER_TOKEN','AG_RUNTIME_TOKEN','AG_INTEGRITY_KEY')) {
        $bytes = [byte[]]::new(32)
        $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
        [Environment]::SetEnvironmentVariable($name, [Convert]::ToBase64String($bytes))
    }
    $env:AG_DATABASE_PATH = Join-Path (Get-Location) ('var\session-' + [guid]::NewGuid().ToString('N') + '.sqlite3')
    Write-Host 'AgentGuard local dashboard: http://127.0.0.1:8000'
    Write-Host ('Owner token for this local session: ' + $env:AG_OWNER_TOKEN)
    Write-Host 'Linux runtime remains unavailable until Member 2 is connected.'
    & .\.venv\Scripts\python.exe -m uvicorn application.api:create_app --factory --host 127.0.0.1 --port 8000 --no-access-log
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $previous[$name]) }
}
