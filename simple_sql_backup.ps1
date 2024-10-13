[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ScriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

function Remove-TempFiles {
    Get-ChildItem -Path $ScriptDirectory -Filter *.bak -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $ScriptDirectory -Filter *.7z -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

$LogFile = "$ScriptDirectory\backup.log"

function Write-LogAndOutput {
    param (
        [string]$Message,
        [bool]$OutputToConsole = $true
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
    $LogMessage = "$Timestamp - $Message"

    if (-not (Test-Path -Path $LogFile)) {
        New-Item -ItemType File -Path $LogFile -Force | Out-Null
    }
    Add-Content -Path $LogFile -Value $LogMessage
    if ($OutputToConsole) {
        Write-Output "$Timestamp - $Message"
    }
}

function Import-Vars {
    $EnvFilePath = Join-Path -Path $ScriptDirectory -ChildPath ".env"
    if (Test-Path -Path $EnvFilePath) {
        $dotenvContent = Get-Content -Path $EnvFilePath
        foreach ($Line in $dotenvContent) {
            if ($Line -match "^\s*#") { continue }
            $Parts = $Line -split "="
            if ($Parts.Length -eq 2) {
                $VariableName = $Parts[0].Trim()
                $VariableValue = $Parts[1].Trim().Trim('"')
                [System.Environment]::SetEnvironmentVariable($VariableName, $VariableValue, "Process")
            }
        }
        $Script:Databases = Get-ChildItem Env: | Where-Object { $_.Name -match '^DB_\d+$' } | ForEach-Object { $_.Value }
    } else {
        $ErrorMessage = "Environment file .env not found at $EnvFilePath"
        Write-LogAndOutput "Error: $ErrorMessage"
        exit 1
    }
}

function Test-EnvVariables {
    $missingErrors = @()
    if (-not $Script:Databases) {
        $missingErrors += "At least one database (DB_1, DB_2, DB_3, etc.) must be set."
    }
    if (-not $env:JOB_NAME) {
        $missingErrors += "JOB_NAME is required."
    }
    $EnableS3 = $env:ENABLE_S3_UPLOAD -eq 'true'
    $EnableSMB = $env:ENABLE_SMB_UPLOAD -eq 'true'
    $EnableTelegram = $env:ENABLE_TELEGRAM -eq 'true'
    if (-not ($EnableS3 -or $EnableSMB)) {
        $missingErrors += "At least one of ENABLE_S3_UPLOAD or ENABLE_SMB_UPLOAD must be true."
    }
    $Requirements = @{
        'S3' = 'PROVIDER', 'ACCESS_KEY', 'SECRET_KEY', 'ENDPOINT', 'BUCKET_NAME'
        'SMB' = 'SMB_UNC_PATH', 'SMB_USERNAME', 'SMB_PASSWORD'
        'TELEGRAM' = 'BOT_TOKEN', 'CHAT_ID'
    }
    foreach ($type in $Requirements.Keys) {
        if (($type -eq 'S3' -and $EnableS3) -or 
            ($type -eq 'SMB' -and $EnableSMB) -or 
            ($type -eq 'TELEGRAM' -and $EnableTelegram)) {
            foreach ($key in $Requirements[$type]) {
                if (-not (Get-Item "Env:$key" -ErrorAction SilentlyContinue).value) {
                    $missingErrors += "$key is required for $type configuration."
                }
            }
        }
    }
    if ($missingErrors) {
        Write-LogAndOutput "Error: $missingErrors"
        exit 1
    }
}

function Send-TelegramMessage {
    param (
        [string]$Message
    )
    $Url = "https://api.telegram.org/bot$($env:BOT_TOKEN)/sendMessage"
    $Params = @{
        chat_id = $env:CHAT_ID
        text    = $Message
    }
    if ($env:ENABLE_TELEGRAM -eq "true") {
        Invoke-RestMethod -Uri $Url -Method Post -ContentType "application/json" -Body ($Params | ConvertTo-Json)
        Write-LogAndOutput "Telegram message sent: $Message"
    }
}

function Install-SqlServerModule {
    try {
        if (-not (Get-Command -Name "Invoke-Sqlcmd" -ErrorAction SilentlyContinue)) {
            Write-LogAndOutput "Installing the SqlServer module from the PowerShell Gallery..."
            Install-Module -Name "SqlServer" -Force -Scope CurrentUser -Repository PSGallery -ErrorAction Stop
            Write-LogAndOutput "SqlServer module installed successfully."
        }
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-LogAndOutput "Failed to install SqlServer module: $ErrorMessage"
        Send-TelegramMessage -Message "[$($env:JOB_NAME)] Failed to install SqlServer module: $ErrorMessage"
        exit 1
    }
}

function Install-7ZipZS {
    try {
        $Script:7ZipZSPath = (Get-ItemProperty -Path 'HKLM:SOFTWARE\7-Zip-Zstandard' -Name 'Path').Path + "7z.exe"
        if (-not (Test-Path -Path $Script:7ZipZSPath)) {
            Write-LogAndOutput "7-Zip ZS not found. Downloading and installing..."
            $7ZUrl = "https://github.com/mcmilk/7-Zip-zstd/releases/download/v22.01-v1.5.5-R3/7z22.01-zstd-x64.exe"
            $7ZInstaller = "$env:TEMP\7zInstaller.exe"
            Invoke-WebRequest -Uri $7ZUrl -OutFile $7ZInstaller
            Start-Process -FilePath $7ZInstaller -ArgumentList "/S" -Wait
            Remove-Item -Path $7ZInstaller -Force
        }
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-LogAndOutput "Failed to download and install 7-Zip ZS: $ErrorMessage"
        Send-TelegramMessage -Message "[$($env:JOB_NAME)] Failed to download and install 7-Zip ZS: $ErrorMessage"
        exit 1
    }
}

function Get-Rclone {
    if ($env:RCLONE_PATH) {
        $Script:RclonePath = $env:RCLONE_PATH
    } else {
        $Script:RclonePath = Join-Path -Path $ScriptDirectory -ChildPath "rclone.exe"
        try {
            if (-not (Test-Path -Path $Script:RclonePath)) {
                Write-LogAndOutput "Downloading rclone from https://downloads.rclone.org/rclone-current-windows-amd64.zip..."
                $RcloneZip = Join-Path -Path $ScriptDirectory -ChildPath "rclone.zip"
                Invoke-WebRequest -Uri "https://downloads.rclone.org/rclone-current-windows-amd64.zip" -OutFile $RcloneZip -ErrorAction Stop
                Expand-Archive -Path $RcloneZip -DestinationPath $ScriptDirectory -Force
                $RcloneExtractedPath = Get-ChildItem -Path "$ScriptDirectory\rclone-*-windows-amd64" | Select-Object -ExpandProperty FullName
                Move-Item -Path $RcloneExtractedPath\rclone.exe -Destination $Script:RclonePath -Force
                Remove-Item -Path $RcloneZip -Force
                Remove-Item -Path "$ScriptDirectory\rclone-*-windows-amd64" -Recurse -Force
                Write-LogAndOutput "rclone downloaded and installed successfully."
            }
        } catch {
            $ErrorMessage = $_.Exception.Message
            Write-LogAndOutput "Failed to download and install rclone: $ErrorMessage"
            Send-TelegramMessage -Message "[$($env:JOB_NAME)] Failed to download and install rclone: $ErrorMessage"
            exit 1
        }
    }
}

function Get-HumanReadableFileSize {
    param (
        [string]$FilePath
    )
    $FileInfo = Get-Item $FilePath
    $SizeInBytes = $FileInfo.Length
    $Sizes = "B", "KB", "MB", "GB", "TB"
    $Index = 0
    while ($SizeInBytes -ge 1024 -and $Index -lt $Sizes.Length) {
        $SizeInBytes = $SizeInBytes / 1024.0
        $Index++
    }
    "{0:N2} {1}" -f $SizeInBytes, $Sizes[$Index]
}

function Backup-Database {
    param (
        [string]$Database,
        [string]$Timestamp
    )
    try {
        Write-LogAndOutput "Starting export of DB $Database..."
        $ExportedDBFile = "$Database-$Timestamp.bak"
        $ExportedDBPath = Join-Path -Path $ScriptDirectory -ChildPath $ExportedDBFile
        if ($env:SQL_USERNAME -and $env:SQL_PASSWORD) {
            Invoke-SqlCmd -Query "BACKUP DATABASE $Database TO DISK = '$ExportedDBPath' WITH INIT;" -ServerInstance $env:SQL_SERVER -Username $env:SQL_USERNAME -Password $env:SQL_PASSWORD -QueryTimeout 0 -ErrorAction Stop
        } else {
            Invoke-SqlCmd -Query "BACKUP DATABASE $Database TO DISK = '$ExportedDBPath' WITH INIT;" -ServerInstance $env:SQL_SERVER -ErrorAction Stop -TrustServerCertificate -QueryTimeout 0
        }
        $Size = Get-HumanReadableFileSize -FilePath $ExportedDBPath
        Write-LogAndOutput "Exporting backup successful for DB $Database. File size is $Size."
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-LogAndOutput "Failed to perform SQL Server backup: $ErrorMessage"
        Send-TelegramMessage -Message "[$($env:JOB_NAME)] Failed to perform export of DB ${Database}: $ErrorMessage"
        exit 1
    }
}

function Compress-Database {
    param (
        [string]$Database,
        [string]$Timestamp
    )
    try {
        $ExportedDBFile = "$Database-$Timestamp.bak"
        $ExportedDBPath = Join-Path -Path $ScriptDirectory -ChildPath $ExportedDBFile
        $CompressedFileName = "$Database-$Timestamp-zstd.7z"
        $CompressedDBPath = Join-Path -Path $ScriptDirectory -ChildPath $CompressedFileName
        & $Script:7ZipZSPath a -m0=zstd -mx1 $CompressedDBPath $ExportedDBPath
        $Size = Get-HumanReadableFileSize -FilePath $CompressedDBPath
        Write-LogAndOutput "Compressing backup successful for DB $Database. File size is $Size."
        $Script:FilesToUpload[$Database] = $CompressedDBPath
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-LogAndOutput "Failed to compress DB export ${ExportedDBFile}: $ErrorMessage"
        Send-TelegramMessage -Message "[$($env:JOB_NAME)] Failed to compress DB export ${ExportedDBFile}: $ErrorMessage"
        exit 1
    }
}

function Move-ToS3 {
    param (
        [string]$FilePath
    )
    $RcloneConfPath = Join-Path -Path $ScriptDirectory -ChildPath "rclone.conf"
    $RcloneConfContent = @(
        "[remote]",
        "type = s3",
        "provider = $($env:PROVIDER)",
        "env_auth = true",
        "access_key_id = $($env:ACCESS_KEY)",
        "secret_access_key = $($env:SECRET_KEY)",
        "endpoint = $($env:ENDPOINT)"
    )
    $RcloneConfContent | Set-Content -Path $RcloneConfPath -Force -ErrorAction Stop
    $File = $(Split-Path -Leaf $FilePath)
    $RcloneDest = "remote:$($env:BUCKET_NAME)/$File"
    Write-LogAndOutput "Starting upload of $File to $($env:PROVIDER)."
    & $Script:RclonePath moveto --config $RcloneConfPath $FilePath $RcloneDest --progress --s3-no-check-bucket 2>> $LogFile
    if ($LASTEXITCODE -eq 0) {
        Write-LogAndOutput "Uploading $File to $($env:PROVIDER) succeeded."
    } else {
        Write-LogAndOutput "Failed to upload to $($env:PROVIDER). See log file for details."
        exit 1
    }
}

function Move-ToSMB {
    param (
        [string]$FilePath
    )
    try {
        $File = $(Split-Path -Leaf $FilePath)
        Write-LogAndOutput "Starting upload of $File to SMB share."
        $SmbUsername = if ($env:SMB_DOMAIN) { "$($env:SMB_DOMAIN)\$($env:SMB_USERNAME)" } else { $env:SMB_USERNAME }
        $Credentials = New-Object System.Management.Automation.PSCredential($SmbUsername, (ConvertTo-SecureString $env:SMB_PASSWORD -AsPlainText -Force))
        $SMBPath = $env:SMB_UNC_PATH.TrimEnd('\')
        New-PSDrive -Name "Z" -PSProvider "FileSystem" -Root $SMBPath -Credential $Credentials -Persist -ErrorAction Stop
        Move-Item -Path $FilePath -Destination "Z:\" -Force
        Remove-PSDrive -Name "Z" -ErrorAction SilentlyContinue
        Write-LogAndOutput "Uploading $File to SMB share succeeded."
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-LogAndOutput "Failed to upload to SMB share: $ErrorMessage"
        Send-TelegramMessage -Message "[$($env:JOB_NAME)] Failed to upload file to SMB: $ErrorMessage"
        exit 1
    }
}

try {
    Write-LogAndOutput "Script execution started."
    Import-Vars
    Test-EnvVariables
    Write-LogAndOutput "Checking for dependencies..."
    Install-SqlServerModule
    Install-7ZipZS
    Write-LogAndOutput "Cleaning working directory..."
    Remove-TempFiles
    Write-LogAndOutput "Starting backup job..."
    $Script:FilesToUpload = @{}
    foreach ($Database in $Script:Databases) {
        $Timestamp = Get-Date -Format 'yyyy_MM_dd-HHmm'
        Backup-Database -Database $Database -Timestamp $Timestamp
        Compress-Database -Database $Database -Timestamp $Timestamp
    }
    if ($env:ENABLE_S3_UPLOAD -eq "true") {
        Get-Rclone
        foreach ($Name in $Script:FilesToUpload.Keys) {
            $FilePath = $Script:FilesToUpload[$Name]
            Move-ToS3 -File $FilePath
        }
    }
    if ($env:ENABLE_SMB_UPLOAD -eq "true") {
        foreach ($Name in $Script:FilesToUpload.Keys) {
            $FilePath = $Script:FilesToUpload[$Name]
            Move-ToSMB -File $FilePath
        }
    }
    Write-LogAndOutput "Cleaning working directory..."
    Remove-TempFiles
    Write-LogAndOutput -Message "Script execution completed."
    Send-TelegramMessage -Message "[$($env:JOB_NAME)] backup job completed successfully."
} catch {
    $ErrorMessage = $_.Exception.Message
    Write-LogAndOutput "Error during script execution: $ErrorMessage"
    Send-TelegramMessage -Message "[$($env:JOB_NAME)] Error during script execution: $ErrorMessage"
    exit 1
}