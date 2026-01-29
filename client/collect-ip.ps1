# =====================================
# IP收集上传脚本 (PowerShell版)
# =====================================

# 配置信息
$UPLOAD_URL = "https://myip.xxx.com/api/upload-ip"
$API_KEY = "your_secret_api_key_here"

$UPLOAD_METHOD = "ftp"

$FTP_HOST = "xxx.com"
$FTP_PORT = 21
$FTP_USER = "user"
$FTP_PASS = "xxxxxxxxx"
$FTP_UPLOAD_DIR = "/api/uploads"

# 文件路径配置
$WORK_DIR = "D:\Program Files\ip"
$IP_HISTORY_FILE = Join-Path $WORK_DIR "ip_history.txt"
$IP_EXPORT_SIMPLE = Join-Path $WORK_DIR "ip_list.txt"
$IP_EXPORT_JSON = Join-Path $WORK_DIR "ip_data.json"
$LOG_FILE = Join-Path $WORK_DIR "collector.log"
$DEVICE_ID_FILE = Join-Path $WORK_DIR "device_id.txt"

# IP收集配置
$MAX_HISTORY_SIZE = 100

# 超时配置
$FTP_TIMEOUT = 30000  # 30秒，单位毫秒
$HTTP_TIMEOUT = 30    # 30秒

# 国内IP查询服务列表
$IP_SERVICES = @(
    "http://ip.3322.net",
    "http://members.3322.org/dyndns/getip",
    "http://pv.sohu.com/cityjson?ie=utf-8",
    "http://myip.ipip.net",
    "http://ip.chinaz.com/getip.aspx",
    "http://www.ip.cn/api/index?ip=&type=0",
    "http://ip.cip.cc",
    "http://ifconfig.me",
    "http://api.ipify.org",
    "http://icanhazip.com",
    "http://ddns.oray.com/checkip",
    "https://api.ipify.org",
    "https://ifconfig.me",
    "https://icanhazip.com"
)

# 重试配置
$MAX_RETRIES = 3
$RETRY_DELAY = 5

# UTF8 无 BOM 编码对象
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False

# 写入日志函数
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    [System.IO.File]::AppendAllText($LOG_FILE, $logMessage + "`n", $Utf8NoBomEncoding)
    Write-Host $logMessage
}

# 创建工作目录
function Initialize-WorkDir {
    if (-not (Test-Path $WORK_DIR)) {
        New-Item -ItemType Directory -Path $WORK_DIR -Force | Out-Null
        Write-Log "创建工作目录: $WORK_DIR"
    }
    
    if (-not (Test-Path $IP_HISTORY_FILE)) {
        New-Item -ItemType File -Path $IP_HISTORY_FILE -Force | Out-Null
    }
}

# 生成或读取设备唯一ID
function Get-DeviceId {
    if (Test-Path $DEVICE_ID_FILE) {
        return [System.IO.File]::ReadAllText($DEVICE_ID_FILE, $Utf8NoBomEncoding).Trim()
    }
    
    $hostname = $env:COMPUTERNAME
    $random_id = "{0:D5}" -f (Get-Random -Maximum 100000)
    $device_id = "$hostname-$random_id"
    
    [System.IO.File]::WriteAllText($DEVICE_ID_FILE, $device_id, $Utf8NoBomEncoding)
    Write-Log "生成设备ID: $device_id"
    
    return $device_id
}

# 解析搜狐返回的IP
function Parse-SohuIP {
    param([string]$Response)
    
    if ($Response -match '"cip"\s*:\s*"([^"]+)"') {
        return $matches[1]
    }
    return $null
}

# 解析myip.ipip.net返回的IP
function Parse-IpipIP {
    param([string]$Response)
    
    if ($Response -match '(?:IP：|IP:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
        return $matches[1]
    }
    if ($Response -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
        return $matches[1]
    }
    return $null
}

# 解析ip.cn返回的IP
function Parse-IpcnIP {
    param([string]$Response)
    
    if ($Response -match '"ip"\s*:\s*"([^"]+)"') {
        return $matches[1]
    }
    if ($Response -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
        return $matches[1]
    }
    return $null
}

# 验证IP格式
function Test-IPAddress {
    param([string]$IP)
    
    # 基本格式验证
    if ($IP -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        return $false
    }
    
    # 验证每个段
    $octets = $IP -split '\.'
    foreach ($octet in $octets) {
        if ([int]$octet -gt 255) {
            return $false
        }
    }
    
    # 排除私有IP
    if ($IP -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)') {
        return $false
    }
    
    # 排除特殊IP
    if ($IP -match '^(0\.|169\.254\.|224\.|240\.)') {
        return $false
    }
    
    return $true
}

# 从单个服务获取IP
function Get-IPFromService {
    param(
        [string]$Service,
        [int]$Timeout = 5
    )
    
    Write-Log "→ 尝试: $Service"
    
    try {
        $response = Invoke-WebRequest -Uri $Service -TimeoutSec $Timeout -UseBasicParsing -ErrorAction Stop
        $content = $response.Content
        
        if ([string]::IsNullOrWhiteSpace($content)) {
            Write-Log "  ✗ 响应为空"
            return $null
        }
        
        $ip = $null
        
        # 根据服务类型解析IP
        if ($Service -like "*sohu.com*") {
            $ip = Parse-SohuIP -Response $content
        }
        elseif ($Service -like "*ipip.net*") {
            $ip = Parse-IpipIP -Response $content
        }
        elseif ($Service -like "*ip.cn*") {
            $ip = Parse-IpcnIP -Response $content
        }
        else {
            if ($content -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                $ip = $matches[1]
            }
        }
        
        if ([string]::IsNullOrWhiteSpace($ip)) {
            Write-Log "  ✗ 无法解析IP"
            return $null
        }
        
        if (Test-IPAddress -IP $ip) {
            Write-Log "  ✓ 检测到IP: $ip"
            return $ip
        }
        else {
            Write-Log "  ✗ IP验证失败: $ip"
            return $null
        }
    }
    catch {
        Write-Log "  ✗ 连接失败: $($_.Exception.Message)"
        return $null
    }
}

# 获取当前公网IP（带重试）
function Get-CurrentIPs {
    $retry_count = 0
    
    while ($retry_count -lt $MAX_RETRIES) {
        if ($retry_count -gt 0) {
            Write-Log "⟳ 第 $($retry_count + 1) 次尝试..."
            Start-Sleep -Seconds $RETRY_DELAY
        }
        else {
            Write-Log "开始检测公网IP..."
        }
        
        $detected_ips = @()
        
        foreach ($service in $IP_SERVICES) {
            $ip = Get-IPFromService -Service $service -Timeout 5
            if ($ip) {
                $detected_ips += $ip
            }
            
            if ($detected_ips.Count -ge 3) {
                break
            }
        }
        
        if ($detected_ips.Count -gt 0) {
            $unique_ips = $detected_ips | Select-Object -Unique
            Write-Log "✓ 检测到 $($unique_ips.Count) 个IP: $($unique_ips -join ', ')"
            return $unique_ips
        }
        
        $retry_count++
    }
    
    Write-Log "✗ 无法获取IP"
    return @()
}

# 添加IP到历史记录
function Add-ToHistory {
    param([array]$IPs)
    
    $device_id = Get-DeviceId
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    foreach ($ip in $IPs) {
        $entry = "$timestamp | Device: $device_id | IP: $ip`n"
        [System.IO.File]::AppendAllText($IP_HISTORY_FILE, $entry, $Utf8NoBomEncoding)
        Write-Log "记录IP: $ip"
    }
    
    # 限制历史文件大小
    if (Test-Path $IP_HISTORY_FILE) {
        $history_lines = [System.IO.File]::ReadAllLines($IP_HISTORY_FILE, $Utf8NoBomEncoding)
        if ($history_lines.Count -gt $MAX_HISTORY_SIZE) {
            $kept_lines = $history_lines | Select-Object -Last $MAX_HISTORY_SIZE
            [System.IO.File]::WriteAllLines($IP_HISTORY_FILE, $kept_lines, $Utf8NoBomEncoding)
        }
    }
}

# 导出简易IP列表
function Export-SimpleList {
    if (Test-Path $IP_HISTORY_FILE) {
        $history_content = [System.IO.File]::ReadAllText($IP_HISTORY_FILE, $Utf8NoBomEncoding)
        $ips = $history_content -split "`n" | 
               ForEach-Object { 
                   if ($_ -match 'IP:\s*(.+)$') { 
                       $matches[1].Trim() 
                   } 
               } | 
               Where-Object { $_ } | 
               Select-Object -Unique
        
        if ($ips.Count -gt 0) {
            $ip_list = $ips -join "`n"
            [System.IO.File]::WriteAllText($IP_EXPORT_SIMPLE, $ip_list, $Utf8NoBomEncoding)
            Write-Log "✓ 导出简易IP列表 ($($ips.Count) 个IP)"
        }
    }
}

# 导出JSON数据
function Export-JsonData {
    try {
        $device_id = Get-DeviceId
        
        # 读取历史记录并统计IP
        $ip_last_seen = @{}
        
        if (Test-Path $IP_HISTORY_FILE) {
            $history_content = [System.IO.File]::ReadAllText($IP_HISTORY_FILE, $Utf8NoBomEncoding)
            $history_lines = $history_content -split "`n"
            
            foreach ($line in $history_lines) {
                if ($line -match '(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*IP:\s*(.+)$') {
                    $timestamp = $matches[1].Trim()
                    $ip = $matches[2].Trim()
                    $ip_last_seen[$ip] = $timestamp
                }
            }
        }
        
        # 使用 ArrayList 而不是数组累加
        $ip_array = New-Object System.Collections.ArrayList
        foreach ($ip in $ip_last_seen.Keys) {
            $ip_obj = [PSCustomObject]@{
                ip = [string]$ip
                last_seen = [string]$ip_last_seen[$ip]
            }
            [void]$ip_array.Add($ip_obj)
        }
        
        # 创建 JSON 对象
        $json_data = [PSCustomObject]@{
            device_id = [string]$device_id
            hostname = [string]$env:COMPUTERNAME
            collected_at = [string](Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            ip_count = [int]$ip_array.Count
            ips = $ip_array.ToArray()
        }
        
        # 转换并保存 JSON（使用无BOM的UTF8编码）
        $json_string = $json_data | ConvertTo-Json -Depth 5 -Compress:$false
        [System.IO.File]::WriteAllText($IP_EXPORT_JSON, $json_string, $Utf8NoBomEncoding)
        
        Write-Log "✓ 导出JSON数据"
    }
    catch {
        Write-Log "✗ JSON导出失败: $($_.Exception.Message)"
        throw
    }
}

# 通过FTP上传文件（改进版）
function Upload-ViaFTP {
    if ([string]::IsNullOrWhiteSpace($FTP_HOST) -or 
        [string]::IsNullOrWhiteSpace($FTP_USER) -or 
        [string]::IsNullOrWhiteSpace($FTP_PASS)) {
        Write-Log "✗ FTP配置不完整"
        return $false
    }
    
    if (-not (Test-Path $IP_EXPORT_JSON)) {
        Write-Log "✗ JSON文件不存在"
        return $false
    }
    
    $device_id = Get-DeviceId
    $remote_filename = "$device_id.json"
    
    Write-Log "📤 通过FTP上传数据..."
    Write-Log "FTP服务器: ${FTP_HOST}:${FTP_PORT}"
    Write-Log "远程文件名: $remote_filename"
    
    try {
        # 构建FTP URL
        $ftp_url = "ftp://${FTP_HOST}:${FTP_PORT}${FTP_UPLOAD_DIR}/${remote_filename}"
        
        # 读取文件内容
        $file_content = [System.IO.File]::ReadAllBytes($IP_EXPORT_JSON)
        
        # 创建FTP请求
        $ftp_request = [System.Net.FtpWebRequest]::Create($ftp_url)
        $ftp_request.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
        $ftp_request.Credentials = New-Object System.Net.NetworkCredential($FTP_USER, $FTP_PASS)
        $ftp_request.UseBinary = $true
        $ftp_request.UsePassive = $true
        $ftp_request.KeepAlive = $false
        $ftp_request.Timeout = $FTP_TIMEOUT
        $ftp_request.ReadWriteTimeout = $FTP_TIMEOUT
        
        # 上传文件
        $request_stream = $ftp_request.GetRequestStream()
        $request_stream.Write($file_content, 0, $file_content.Length)
        $request_stream.Close()
        $request_stream.Dispose()
        
        # 获取响应
        $response = $ftp_request.GetResponse()
        Write-Log "✓✓✓ FTP上传成功 (状态: $($response.StatusDescription))"
        Write-Log "远程路径: ${FTP_UPLOAD_DIR}/${remote_filename}"
        $response.Close()
        
        # 同时上传简易IP列表
        if (Test-Path $IP_EXPORT_SIMPLE) {
            try {
                $txt_url = "ftp://${FTP_HOST}:${FTP_PORT}${FTP_UPLOAD_DIR}/${device_id}.txt"
                $txt_content = [System.IO.File]::ReadAllBytes($IP_EXPORT_SIMPLE)
                
                $txt_request = [System.Net.FtpWebRequest]::Create($txt_url)
                $txt_request.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
                $txt_request.Credentials = New-Object System.Net.NetworkCredential($FTP_USER, $FTP_PASS)
                $txt_request.UseBinary = $true
                $txt_request.UsePassive = $true
                $txt_request.KeepAlive = $false
                $txt_request.Timeout = $FTP_TIMEOUT
                $txt_request.ReadWriteTimeout = $FTP_TIMEOUT
                
                $txt_stream = $txt_request.GetRequestStream()
                $txt_stream.Write($txt_content, 0, $txt_content.Length)
                $txt_stream.Close()
                $txt_stream.Dispose()
                
                $txt_response = $txt_request.GetResponse()
                $txt_response.Close()
                
                Write-Log "✓ 同时上传了TXT文件"
            }
            catch {
                Write-Log "⚠️  TXT文件上传失败: $($_.Exception.Message)"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "✗✗✗ FTP上传失败"
        Write-Log "错误: $($_.Exception.Message)"
        
        # 解释常见错误
        $error_msg = $_.Exception.Message
        if ($error_msg -like "*550*") {
            Write-Log "原因: 远程文件未找到或无权限"
        }
        elseif ($error_msg -like "*530*") {
            Write-Log "原因: FTP登录失败（用户名或密码错误）"
        }
        elseif ($error_msg -like "*timeout*" -or $error_msg -like "*超时*") {
            Write-Log "原因: FTP连接超时"
        }
        
        return $false
    }
}

# 通过HTTP API上传数据
function Upload-ViaHTTP {
    if ([string]::IsNullOrWhiteSpace($UPLOAD_URL)) {
        Write-Log "⚠️  未配置HTTP上传URL"
        return $false
    }
    
    if (-not (Test-Path $IP_EXPORT_JSON)) {
        Write-Log "✗ JSON文件不存在"
        return $false
    }
    
    Write-Log "📤 通过HTTP API上传数据..."
    Write-Log "目标URL: $UPLOAD_URL"
    
    try {
        $json_content = [System.IO.File]::ReadAllText($IP_EXPORT_JSON, $Utf8NoBomEncoding)
        
        $headers = @{
            "Content-Type" = "application/json"
            "X-API-Key" = $API_KEY
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        $response = Invoke-WebRequest -Uri $UPLOAD_URL `
                                       -Method Post `
                                       -Headers $headers `
                                       -Body $json_content `
                                       -TimeoutSec $HTTP_TIMEOUT `
                                       -UseBasicParsing `
                                       -ErrorAction Stop
        
        Write-Log "✓✓✓ HTTP上传成功 (HTTP $($response.StatusCode))"
        Write-Log "服务器响应: $($response.Content)"
        
        return $true
    }
    catch {
        $status_code = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "N/A" }
        Write-Log "✗✗✗ HTTP上传失败 (HTTP $status_code)"
        Write-Log "错误详情: $($_.Exception.Message)"
        
        return $false
    }
}

# 上传数据到服务器
function Upload-ToServer {
    Write-Log "开始上传数据..."
    
    switch ($UPLOAD_METHOD.ToLower()) {
        "ftp" {
            $result = Upload-ViaFTP
            
            # 如果FTP失败,尝试HTTP作为备选
            if (-not $result) {
                Write-Log "⚠️  FTP上传失败,尝试HTTP方式..."
                return Upload-ViaHTTP
            }
            return $result
        }
        "http" {
            return Upload-ViaHTTP
        }
        default {
            Write-Log "✗ 未知的上传方式: $UPLOAD_METHOD"
            return $false
        }
    }
}

# 主函数
function Main {
    Write-Log ""
    Write-Log "========================================"
    Write-Log "IP收集任务开始"
    Write-Log "========================================"
    
    # 初始化
    Initialize-WorkDir
    
    # 获取设备ID
    $device_id = Get-DeviceId
    Write-Log "设备ID: $device_id"
    
    # 获取当前IP
    $current_ips = Get-CurrentIPs
    
    if ($current_ips.Count -eq 0) {
        Write-Log "✗ 无法获取IP,任务终止"
        Write-Log "========================================"
        Write-Host ""
        Write-Host "按任意键退出..." -ForegroundColor Yellow
        Read-Host
        exit 1
    }
    
    # 添加到历史
    Add-ToHistory -IPs $current_ips
    
    # 导出文件
    Export-SimpleList
    Export-JsonData
    
    # 上传到服务器
    $upload_result = Upload-ToServer
    
    Write-Log "任务完成"
    Write-Log "========================================"
    
    # 显示输出文件
    Write-Host ""
    Write-Host "生成的文件：" -ForegroundColor Green
    Write-Host "  简易列表: $IP_EXPORT_SIMPLE"
    Write-Host "  JSON数据: $IP_EXPORT_JSON"
    Write-Host "  设备ID:   $device_id"
    Write-Host ""
    
    # 自动退出提示
    Write-Host "脚本将在 3 秒后自动退出..." -ForegroundColor Cyan
    Start-Sleep -Seconds 3
}

# 执行主函数
try {
    Main
    Write-Host "脚本执行完毕，正在退出..." -ForegroundColor Green
    exit 0
}
catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "脚本执行出错:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "按 Enter 键退出..." -ForegroundColor Yellow
    Read-Host
    exit 1
}
