# simple_sql_backup.ps1

A comprehensive PowerShell script designed to back up one or more MSSQL databases on a Windows host, compress them, and upload them to an S3-compatible provider or SMB share of your choice. It also includes support for Telegram notifications.

This script leverages the following open-source projects:
- Microsoft's [SqlServer PowerShell Module](https://github.com/microsoft/SQLServerPSModule)
- Tino Reichardt's [7Zip ZS](https://github.com/mcmilk/7-Zip-zstd)
- The cloud storage Swiss Army Knife [rclone](https://rclone.org)

## Features:
- Automatic dependency management
- Automatic rclone configuration
- Capability to back up multiple databases
- Support for both SQL and Windows authentication
- Utilizes [ZStandard](https://github.com/facebook/zstd) at Level 1 for an optimal balance of compression speed and storage efficiency
- Uploads to any S3-compatible storage provider
- Uploads to any SMB share
- Windows Task Scheduler Safe™ thanks to robust error-checking
- Comprehensive logging to file and alerting via Telegram
- dotenv configuration management

## Instructions:
- Copy `sample.env` to `.env` and edit the values to match your environment.
- You may add more `DB_n` variables as required.
- Commenting out either `SQL_USERNAME` or `SQL_PASSWORD` will revert the script to Windows Authentication. Ensure the user running the scheduled task has access to the database(s).
- If you already have the rclone binary installed, you can optionally point the script to it, and it will use that instead of downloading it from the web.
- Add the script as an action in your scheduled backup task.

This script requires PowerShell version 5.1 or later.
