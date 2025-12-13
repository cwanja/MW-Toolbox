<#
.SYNOPSIS
    Identifies processes and system resources causing machine lag.

.DESCRIPTION
    This script analyzes CPU, memory, disk, and network usage to help identify
    what is causing system performance issues. It provides detailed information
    about resource-intensive processes and system bottlenecks.

.PARAMETER TopProcessCount
    Number of top processes to display for each resource category. Default is 10.

.PARAMETER MonitorDuration
    Duration in seconds to monitor system performance. Default is 30 seconds.

.PARAMETER IncludeDiskIO
    Include disk I/O analysis (may require elevated permissions).

.EXAMPLE
    .\Get-SystemPerformanceAnalysis.ps1
    Runs a standard performance analysis with default settings.

.EXAMPLE
    .\Get-SystemPerformanceAnalysis.ps1 -TopProcessCount 15 -MonitorDuration 60
    Monitors for 60 seconds and shows top 15 processes for each category.

.EXAMPLE
    .\Get-SystemPerformanceAnalysis.ps1 -IncludeDiskIO
    Includes detailed disk I/O analysis (requires admin rights).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$TopProcessCount = 10,
    
    [Parameter(Mandatory = $false)]
    [int]$MonitorDuration = 30,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDiskIO
)

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Get-FormattedBytes {
    param([long]$Bytes)
    if ($Bytes -gt 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    elseif ($Bytes -gt 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    elseif ($Bytes -gt 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    else { return "$Bytes Bytes" }
}

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

Write-Host "Starting System Performance Analysis..." -ForegroundColor Green
Write-Host "Monitor Duration: $MonitorDuration seconds" -ForegroundColor Yellow
Write-Host "Admin Rights: $isAdmin" -ForegroundColor $(if($isAdmin){"Green"}else{"Yellow"})

# System Overview
Write-SectionHeader "System Overview"

$computerSystem = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1

Write-Host "Computer Name: $($computerSystem.Name)"
Write-Host "OS: $($os.Caption) ($($os.Version))"
Write-Host "CPU: $($cpu.Name)"
Write-Host "Total Physical Memory: $(Get-FormattedBytes $computerSystem.TotalPhysicalMemory)"
Write-Host "Available Memory: $(Get-FormattedBytes $os.FreePhysicalMemory * 1KB)"
Write-Host "Memory Usage: $([math]::Round((($computerSystem.TotalPhysicalMemory - ($os.FreePhysicalMemory * 1KB)) / $computerSystem.TotalPhysicalMemory) * 100, 2))%"

# CPU Analysis
Write-SectionHeader "CPU Analysis"

Write-Host "Collecting CPU usage data for $MonitorDuration seconds..." -ForegroundColor Yellow

# Get initial CPU time
$processes1 = Get-Process | Where-Object { $_.CPU -ne $null } | 
    Select-Object Id, ProcessName, CPU, @{Name='CPUTime1';Expression={$_.TotalProcessorTime}}

Start-Sleep -Seconds $MonitorDuration

# Get final CPU time and calculate usage
$processes2 = Get-Process | Where-Object { $_.CPU -ne $null } | 
    Select-Object Id, ProcessName, CPU, @{Name='CPUTime2';Expression={$_.TotalProcessorTime}}

$cpuUsage = foreach ($p2 in $processes2) {
    $p1 = $processes1 | Where-Object { $_.Id -eq $p2.Id }
    if ($p1) {
        $cpuDelta = ($p2.CPUTime2 - $p1.CPUTime1).TotalSeconds
        $cpuPercent = [math]::Round(($cpuDelta / $MonitorDuration) * 100 / $env:NUMBER_OF_PROCESSORS, 2)
        
        [PSCustomObject]@{
            ProcessName = $p2.ProcessName
            PID = $p2.Id
            'CPU %' = $cpuPercent
            'Total CPU (s)' = [math]::Round($p2.CPU, 2)
        }
    }
}

$topCPU = $cpuUsage | Where-Object { $_.'CPU %' -gt 0 } | 
    Sort-Object 'CPU %' -Descending | 
    Select-Object -First $TopProcessCount

Write-Host "Top $TopProcessCount CPU-Intensive Processes:" -ForegroundColor Green
$topCPU | Format-Table -AutoSize

# Overall CPU Load
$cpuLoad = Get-CimInstance Win32_Processor | 
    Measure-Object -Property LoadPercentage -Average | 
    Select-Object -ExpandProperty Average

Write-Host "Overall CPU Load: $cpuLoad%" -ForegroundColor $(if($cpuLoad -gt 80){"Red"}elseif($cpuLoad -gt 50){"Yellow"}else{"Green"})

# Memory Analysis
Write-SectionHeader "Memory Analysis"

$processes = Get-Process | Where-Object { $_.WorkingSet -gt 0 } | 
    Select-Object ProcessName, Id, 
        @{Name='Memory (MB)';Expression={[math]::Round($_.WorkingSet / 1MB, 2)}},
        @{Name='Peak Memory (MB)';Expression={[math]::Round($_.PeakWorkingSet / 1MB, 2)}},
        @{Name='Private Memory (MB)';Expression={[math]::Round($_.PrivateMemorySize / 1MB, 2)}}

$topMemory = $processes | Sort-Object 'Memory (MB)' -Descending | Select-Object -First $TopProcessCount

Write-Host "Top $TopProcessCount Memory-Intensive Processes:" -ForegroundColor Green
$topMemory | Format-Table -AutoSize

$totalUsedMemory = ($processes | Measure-Object 'Memory (MB)' -Sum).Sum
Write-Host "Total Memory Used by Processes: $('{0:N2}' -f $totalUsedMemory) MB" -ForegroundColor Yellow

# Handle Analysis
Write-SectionHeader "Handle Analysis"

$handles = Get-Process | Where-Object { $_.HandleCount -gt 0 } | 
    Select-Object ProcessName, Id, HandleCount, 
        @{Name='Threads';Expression={$_.Threads.Count}} | 
    Sort-Object HandleCount -Descending | 
    Select-Object -First $TopProcessCount

Write-Host "Top $TopProcessCount Processes by Handle Count:" -ForegroundColor Green
$handles | Format-Table -AutoSize

# Disk Analysis
Write-SectionHeader "Disk Usage"

$disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | 
    Select-Object DeviceID, 
        @{Name='Size (GB)';Expression={[math]::Round($_.Size / 1GB, 2)}},
        @{Name='Free (GB)';Expression={[math]::Round($_.FreeSpace / 1GB, 2)}},
        @{Name='Used %';Expression={[math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 2)}}

Write-Host "Disk Space:" -ForegroundColor Green
$disks | Format-Table -AutoSize

# Disk I/O Analysis (if admin and requested)
if ($IncludeDiskIO) {
    if ($isAdmin) {
        Write-Host "`nCollecting Disk I/O data for $MonitorDuration seconds..." -ForegroundColor Yellow
        
        $diskIO1 = Get-Counter '\Process(*)\IO Data Bytes/sec' -ErrorAction SilentlyContinue
        Start-Sleep -Seconds $MonitorDuration
        $diskIO2 = Get-Counter '\Process(*)\IO Data Bytes/sec' -ErrorAction SilentlyContinue
        
        if ($diskIO2) {
            $topDiskIO = $diskIO2.CounterSamples | 
                Where-Object { $_.CookedValue -gt 0 } | 
                Sort-Object CookedValue -Descending | 
                Select-Object -First $TopProcessCount @{Name='Process';Expression={$_.InstanceName}}, 
                    @{Name='IO (MB/s)';Expression={[math]::Round($_.CookedValue / 1MB, 2)}}
            
            Write-Host "`nTop $TopProcessCount Processes by Disk I/O:" -ForegroundColor Green
            $topDiskIO | Format-Table -AutoSize
        }
    } else {
        Write-Host "Disk I/O analysis requires administrator privileges." -ForegroundColor Red
    }
}

# Network Analysis
Write-SectionHeader "Network Interfaces"

$networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | 
    Select-Object Name, InterfaceDescription, LinkSpeed, Status

Write-Host "Active Network Adapters:" -ForegroundColor Green
$networkAdapters | Format-Table -AutoSize

# Service Analysis
Write-SectionHeader "Service Status"

$services = Get-Service | Where-Object { $_.Status -eq 'Running' } | 
    Measure-Object | Select-Object -ExpandProperty Count

Write-Host "Running Services: $services" -ForegroundColor Yellow

$autoServices = Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' }
if ($autoServices) {
    Write-Host "`nAutomatic Services Not Running:" -ForegroundColor Red
    $autoServices | Select-Object Name, DisplayName, Status | Format-Table -AutoSize
}

# Startup Programs
Write-SectionHeader "Startup Programs"

$startupApps = Get-CimInstance Win32_StartupCommand | 
    Select-Object Name, Command, Location, User

Write-Host "Startup Programs Count: $($startupApps.Count)" -ForegroundColor Yellow
if ($startupApps.Count -gt 0) {
    Write-Host "`nTop Startup Programs:" -ForegroundColor Green
    $startupApps | Select-Object -First 10 Name, Location | Format-Table -AutoSize
}

# System Uptime
Write-SectionHeader "System Information"

$uptime = (Get-Date) - $os.LastBootUpTime
Write-Host "System Uptime: $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes" -ForegroundColor Yellow

# Performance Recommendations
Write-SectionHeader "Performance Recommendations"

$recommendations = @()

if ($cpuLoad -gt 80) {
    $recommendations += "⚠️ HIGH CPU USAGE: Consider closing unnecessary applications or upgrading CPU."
}

$memoryUsagePercent = [math]::Round((($computerSystem.TotalPhysicalMemory - ($os.FreePhysicalMemory * 1KB)) / $computerSystem.TotalPhysicalMemory) * 100, 2)
if ($memoryUsagePercent -gt 85) {
    $recommendations += "⚠️ HIGH MEMORY USAGE: Close unused applications or add more RAM."
}

$criticalDisk = $disks | Where-Object { $_.'Used %' -gt 90 }
if ($criticalDisk) {
    $recommendations += "⚠️ LOW DISK SPACE: Free up space on drive(s): $($criticalDisk.DeviceID -join ', ')"
}

if ($topCPU | Where-Object { $_.'CPU %' -gt 50 }) {
    $highCPUProcess = ($topCPU | Where-Object { $_.'CPU %' -gt 50 } | Select-Object -First 1).ProcessName
    $recommendations += "⚠️ Process '$highCPUProcess' is using excessive CPU. Consider restarting it."
}

if ($handles | Where-Object { $_.HandleCount -gt 10000 }) {
    $highHandleProcess = ($handles | Where-Object { $_.HandleCount -gt 10000 } | Select-Object -First 1).ProcessName
    $recommendations += "⚠️ Process '$highHandleProcess' has excessive handles. May indicate a resource leak."
}

if ($startupApps.Count -gt 20) {
    $recommendations += "ℹ️ You have $($startupApps.Count) startup programs. Consider disabling unnecessary ones."
}

if ($recommendations.Count -eq 0) {
    Write-Host "✅ No immediate performance issues detected!" -ForegroundColor Green
} else {
    foreach ($rec in $recommendations) {
        Write-Host $rec -ForegroundColor Yellow
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Analysis Complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan
