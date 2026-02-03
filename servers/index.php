<?php
/**
 * IP收集整合API 
 * 功能：接收IP数据（HTTP/FTP）、去重整合、频率限制、Web界面显示
 * 
 * 上传流程：
 * 1. HTTP/FTP 上传 → /api/uploads/ (临时目录)
 * 2. processor.php 处理 → /api/ip_data/ (最终存储)
 * 3. 自动合并生成统计数据
 */

// ==================== 路径路由解析 ====================
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// 路径映射到action
$pathRoutes = [
    '/api/upload-ip' => 'upload',
    '/api/upload'    => 'upload',
    '/api/list'      => 'list',
    '/api/stats'     => 'stats',
    '/api/ips'       => 'ips',
    '/api/json'      => 'json',
    '/api/merge'     => 'merge',
    '/api/process'   => 'process',  // 处理上传文件
];

// 检查路径并设置action
foreach ($pathRoutes as $path => $action) {
    if (strpos($requestUri, $path) === 0) {
        $_GET['action'] = $action;
        break;
    }
}

// ==================== 配置 ====================
define('API_KEY', 'your_secret_api_key_here135');
define('UPLOAD_DIR', __DIR__ . '/api/uploads');        // 上传临时目录 (FTP/HTTP共用)
define('DATA_DIR', __DIR__ . '/api/ip_data');          // 最终数据目录
define('MERGED_FILE', DATA_DIR . '/merged_ips.json');
define('SIMPLE_LIST', DATA_DIR . '/ip_list.txt');
define('RATE_LIMIT_FILE', DATA_DIR . '/rate_limits.json');
define('DEBUG_LOG', DATA_DIR . '/api_debug.log');

// 限制配置
define('MAX_UPLOAD_SIZE', 1048576);
define('RATE_LIMIT_WINDOW', 300);
define('MAX_UPLOADS_PER_WINDOW', 10);
define('RATE_LIMIT_BY_IP', true);

// 创建必要的目录
foreach ([UPLOAD_DIR, DATA_DIR] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

// CORS设置
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET');
header('Access-Control-Allow-Headers: Content-Type, X-API-Key');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

/**
 * 写入调试日志
 */
function writeDebugLog($message) {
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "[$timestamp] $message\n";
    file_put_contents(DEBUG_LOG, $logMessage, FILE_APPEND);
}

/**
 * 获取客户端IP
 */
function getClientIP() {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? 
          $_SERVER['HTTP_X_REAL_IP'] ?? 
          $_SERVER['REMOTE_ADDR'] ?? 
          'unknown';
    
    if (strpos($ip, ',') !== false) {
        $ip = trim(explode(',', $ip)[0]);
    }
    
    return $ip;
}

/**
 * 检查频率限制
 */
function checkRateLimit($identifier) {
    $rateLimits = [];
    
    if (file_exists(RATE_LIMIT_FILE)) {
        $rateLimits = json_decode(file_get_contents(RATE_LIMIT_FILE), true) ?: [];
    }
    
    $now = time();
    $windowStart = $now - RATE_LIMIT_WINDOW;
    
    foreach ($rateLimits as $id => $timestamps) {
        $rateLimits[$id] = array_filter($timestamps, function($ts) use ($windowStart) {
            return $ts > $windowStart;
        });
        
        if (empty($rateLimits[$id])) {
            unset($rateLimits[$id]);
        }
    }
    
    $uploads = $rateLimits[$identifier] ?? [];
    
    if (count($uploads) >= MAX_UPLOADS_PER_WINDOW) {
        return false;
    }
    
    $rateLimits[$identifier][] = $now;
    file_put_contents(RATE_LIMIT_FILE, json_encode($rateLimits));
    
    return true;
}

/**
 * 验证API密钥
 */
function validateApiKey() {
    $headers = getallheaders();
    
    $apiKey = '';
    $headerFound = '';
    
    foreach ($headers as $name => $value) {
        if (strtolower($name) === 'x-api-key') {
            $apiKey = $value;
            $headerFound = $name;
            break;
        }
    }
    
    if (empty($apiKey)) {
        $apiKey = $_GET['api_key'] ?? '';
        if (!empty($apiKey)) {
            $headerFound = 'GET parameter';
        }
    }
    
    $debugInfo = [
        'timestamp' => date('Y-m-d H:i:s'),
        'client_ip' => getClientIP(),
        'method' => $_SERVER['REQUEST_METHOD'],
        'uri' => $_SERVER['REQUEST_URI'],
        'received_key' => $apiKey,
        'header_found' => $headerFound,
        'match' => ($apiKey === API_KEY) ? 'YES' : 'NO'
    ];
    
    writeDebugLog("API Key验证: " . json_encode($debugInfo, JSON_UNESCAPED_UNICODE));
    
    if ($apiKey !== API_KEY) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => 'Invalid API key',
            'code' => 401,
            'debug' => [
                'received' => substr($apiKey, 0, 10) . '...',
                'length' => strlen($apiKey),
                'header_found' => $headerFound
            ]
        ]);
        exit;
    }
    
    writeDebugLog("✓ API Key验证成功");
}

/**
 * 检查上传大小
 */
function checkUploadSize() {
    $contentLength = $_SERVER['CONTENT_LENGTH'] ?? 0;
    
    if ($contentLength > MAX_UPLOAD_SIZE) {
        http_response_code(413);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => 'Upload size exceeds limit',
            'max_size' => MAX_UPLOAD_SIZE,
            'your_size' => $contentLength,
            'code' => 413
        ]);
        exit;
    }
}

/**
 * 接收上传的IP数据 (保存到uploads目录)
 */
function handleUpload() {
    writeDebugLog("========== 新的HTTP上传请求 ==========");
    
    validateApiKey();
    checkUploadSize();
    
    $identifier = RATE_LIMIT_BY_IP ? getClientIP() : ($_POST['device_id'] ?? 'unknown');
    
    if (!checkRateLimit($identifier)) {
        http_response_code(429);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => 'Rate limit exceeded',
            'limit' => MAX_UPLOADS_PER_WINDOW . ' uploads per ' . (RATE_LIMIT_WINDOW / 60) . ' minutes',
            'code' => 429
        ]);
        writeDebugLog("✗ 频率限制: $identifier");
        return;
    }
    
    $json = file_get_contents('php://input');
    writeDebugLog("收到数据长度: " . strlen($json) . " bytes");
    
    $data = json_decode($json, true);
    
    if (!$data || !isset($data['device_id']) || !isset($data['ips'])) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid data format', 'code' => 400]);
        writeDebugLog("✗ 数据格式错误");
        return;
    }
    
    // ⭐ 保存到 uploads 目录（和FTP上传统一）
    $deviceId = preg_replace('/[^a-zA-Z0-9_-]/', '', $data['device_id']);
    $uploadFile = UPLOAD_DIR . '/' . $deviceId . '.json';
    
    file_put_contents($uploadFile, json_encode($data, JSON_PRETTY_PRINT));
    writeDebugLog("✓ 保存到上传目录: $uploadFile (IP数量: " . count($data['ips']) . ")");
    
    // ⭐ 立即处理这个文件
    $processed = processUploadedFiles();
    
    http_response_code(200);
    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'device_id' => $deviceId,
        'ip_count' => count($data['ips']),
        'processed' => $processed,
        'message' => 'Data uploaded and processed successfully'
    ]);
    
    writeDebugLog("✓✓✓ HTTP上传成功完成");
}

/**
 * 处理上传目录中的文件
 */
function processUploadedFiles() {
    writeDebugLog("开始处理上传文件...");
    
    $uploadedFiles = glob(UPLOAD_DIR . '/*.json');
    $processedCount = 0;
    $errorCount = 0;
    
    foreach ($uploadedFiles as $file) {
        $filename = basename($file);
        writeDebugLog("  处理文件: {$filename}");
        
        try {
            $content = file_get_contents($file);
            $data = json_decode($content, true);
            
            if (!$data || !isset($data['device_id']) || !isset($data['ips'])) {
                writeDebugLog("  ✗ 文件格式无效: {$filename}");
                $errorCount++;
                continue;
            }
            
            // 保存到数据目录
            $deviceId = preg_replace('/[^a-zA-Z0-9_-]/', '', $data['device_id']);
            $targetFile = DATA_DIR . '/' . $deviceId . '.json';
            
            file_put_contents($targetFile, json_encode($data, JSON_PRETTY_PRINT));
            writeDebugLog("  ✓ 已保存到数据目录: {$targetFile}");
            
            // 删除上传目录中的文件
            unlink($file);
            
            $processedCount++;
            
        } catch (Exception $e) {
            writeDebugLog("  ✗ 处理失败: " . $e->getMessage());
            $errorCount++;
        }
    }
    
    writeDebugLog("处理完成: 成功 {$processedCount} 个, 失败 {$errorCount} 个");
    
    // 如果有文件被处理，触发合并
    if ($processedCount > 0) {
        mergeAllIPs();
    }
    
    return $processedCount;
}

/**
 * 合并所有设备的IP数据
 */
function mergeAllIPs() {
    writeDebugLog("开始合并IP数据...");
    
    $allIPs = [];
    $deviceData = [];
    
    $files = glob(DATA_DIR . '/*.json');
    foreach ($files as $file) {
        $basename = basename($file);
        if (in_array($basename, ['merged_ips.json', 'rate_limits.json'])) {
            continue;
        }
        
        $content = file_get_contents($file);
        $data = json_decode($content, true);
        
        if (!$data || !isset($data['ips'])) {
            continue;
        }
        
        $deviceId = $data['device_id'] ?? basename($file, '.json');
        $deviceData[$deviceId] = [
            'device_id' => $deviceId,
            'hostname' => $data['hostname'] ?? 'unknown',
            'last_update' => $data['collected_at'] ?? '',
            'ip_count' => count($data['ips'])
        ];
        
        foreach ($data['ips'] as $ipInfo) {
            $ip = $ipInfo['ip'];
            $lastSeen = $ipInfo['last_seen'] ?? '';
            
            if (!isset($allIPs[$ip]) || $lastSeen > $allIPs[$ip]['last_seen']) {
                $allIPs[$ip] = [
                    'ip' => $ip,
                    'last_seen' => $lastSeen,
                    'devices' => []
                ];
            }
            
            if (!in_array($deviceId, $allIPs[$ip]['devices'])) {
                $allIPs[$ip]['devices'][] = $deviceId;
            }
        }
    }
    
    $merged = [
        'updated_at' => date('Y-m-d H:i:s'),
        'total_ips' => count($allIPs),
        'total_devices' => count($deviceData),
        'devices' => array_values($deviceData),
        'ips' => array_values($allIPs)
    ];
    
    file_put_contents(MERGED_FILE, json_encode($merged, JSON_PRETTY_PRINT));
    
    $simpleList = array_keys($allIPs);
    sort($simpleList);
    file_put_contents(SIMPLE_LIST, implode("\n", $simpleList));
    
    writeDebugLog("合并完成: {$merged['total_ips']} 个IP, {$merged['total_devices']} 个设备");
    
    return $merged;
}

/**
 * 获取合并后的IP列表
 */
function getIPList() {
    $format = $_GET['format'] ?? 'json';
    
    if ($format === 'txt') {
        header('Content-Type: text/plain');
        if (file_exists(SIMPLE_LIST)) {
            readfile(SIMPLE_LIST);
        } else {
            echo '';
        }
    } else {
        header('Content-Type: application/json');
        if (file_exists(MERGED_FILE)) {
            readfile(MERGED_FILE);
        } else {
            echo json_encode([
                'updated_at' => date('Y-m-d H:i:s'),
                'total_ips' => 0,
                'total_devices' => 0,
                'devices' => [],
                'ips' => []
            ]);
        }
    }
}

/**
 * 获取统计信息
 */
function getStats() {
    header('Content-Type: application/json');
    
    if (!file_exists(MERGED_FILE)) {
        echo json_encode([
            'total_ips' => 0,
            'total_devices' => 0,
            'last_update' => null
        ]);
        return;
    }
    
    $data = json_decode(file_get_contents(MERGED_FILE), true);
    
    echo json_encode([
        'total_ips' => $data['total_ips'] ?? 0,
        'total_devices' => $data['total_devices'] ?? 0,
        'last_update' => $data['updated_at'] ?? null,
        'devices' => $data['devices'] ?? []
    ]);
}

/**
 * 显示Web界面
 */
function showWebUI() {
    $data = [];
    if (file_exists(MERGED_FILE)) {
        $data = json_decode(file_get_contents(MERGED_FILE), true);
    }
    
    $totalIPs = $data['total_ips'] ?? 0;
    $totalDevices = $data['total_devices'] ?? 0;
    $lastUpdate = $data['updated_at'] ?? 'Never';
    $devices = $data['devices'] ?? [];
    $ips = $data['ips'] ?? [];
    
    // 统计待处理文件
    $pendingUploads = count(glob(UPLOAD_DIR . '/*.json'));
    
    ?>
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IP白名单管理系统</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            .header {
                background: white;
                border-radius: 10px;
                padding: 30px;
                margin-bottom: 20px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            .header h1 {
                color: #333;
                margin-bottom: 10px;
                font-size: 28px;
            }
            .header p {
                color: #666;
                font-size: 14px;
            }
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }
            .stat-card {
                background: white;
                border-radius: 10px;
                padding: 25px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                transition: transform 0.2s;
            }
            .stat-card:hover {
                transform: translateY(-5px);
            }
            .stat-card h3 {
                color: #999;
                font-size: 14px;
                font-weight: 500;
                margin-bottom: 10px;
                text-transform: uppercase;
            }
            .stat-card .value {
                color: #667eea;
                font-size: 36px;
                font-weight: bold;
            }
            .stat-card.warning .value {
                color: #f39c12;
            }
            .content {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
            }
            @media (max-width: 768px) {
                .content { grid-template-columns: 1fr; }
            }
            .card {
                background: white;
                border-radius: 10px;
                padding: 25px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            .card h2 {
                color: #333;
                font-size: 20px;
                margin-bottom: 20px;
                padding-bottom: 10px;
                border-bottom: 2px solid #667eea;
            }
            .ip-list {
                max-height: 400px;
                overflow-y: auto;
                font-family: "Monaco", "Courier New", monospace;
                font-size: 14px;
                line-height: 1.8;
            }
            .ip-item {
                padding: 8px 12px;
                background: #f5f5f5;
                border-radius: 5px;
                margin-bottom: 8px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .ip-item:hover {
                background: #e8e8e8;
            }
            .ip-address {
                color: #667eea;
                font-weight: bold;
            }
            .device-list {
                max-height: 400px;
                overflow-y: auto;
            }
            .device-item {
                padding: 15px;
                background: #f9f9f9;
                border-radius: 5px;
                margin-bottom: 10px;
                border-left: 4px solid #667eea;
            }
            .device-name {
                font-weight: bold;
                color: #333;
                margin-bottom: 5px;
            }
            .device-info {
                font-size: 13px;
                color: #666;
            }
            .copy-btn, .process-btn {
                background: #667eea;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 12px;
                transition: background 0.2s;
                margin-right: 10px;
            }
            .copy-btn:hover, .process-btn:hover {
                background: #5568d3;
            }
            .badge {
                display: inline-block;
                padding: 3px 8px;
                background: #667eea;
                color: white;
                border-radius: 3px;
                font-size: 11px;
                margin-left: 5px;
            }
            .refresh-btn {
                background: #28a745;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 14px;
                margin-top: 10px;
            }
            .refresh-btn:hover {
                background: #218838;
            }
            .api-info {
                background: #fff3cd;
                border: 1px solid #ffc107;
                border-radius: 5px;
                padding: 15px;
                margin-top: 20px;
                font-size: 13px;
            }
            .api-info strong {
                color: #856404;
            }
            .api-info code {
                background: #fff;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 12px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🌐 IP白名单管理系统</h1>
                <p>最后更新: <?= htmlspecialchars($lastUpdate) ?></p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>总IP数量</h3>
                    <div class="value"><?= $totalIPs ?></div>
                </div>
                <div class="stat-card">
                    <h3>设备数量</h3>
                    <div class="value"><?= $totalDevices ?></div>
                </div>
                <div class="stat-card <?= $pendingUploads > 0 ? 'warning' : '' ?>">
                    <h3>待处理文件</h3>
                    <div class="value"><?= $pendingUploads ?></div>
                </div>
                <div class="stat-card">
                    <h3>最后更新</h3>
                    <div class="value" style="font-size: 16px;"><?= htmlspecialchars($lastUpdate) ?></div>
                </div>
            </div>
            
            <?php if ($pendingUploads > 0): ?>
            <div class="card" style="margin-bottom: 20px; background: #fff3cd; border: 2px solid #ffc107;">
                <h2>⚠️ 待处理上传文件</h2>
                <p style="margin-bottom: 15px;">有 <?= $pendingUploads ?> 个文件等待处理</p>
                <button class="process-btn" onclick="processFiles()">立即处理</button>
            </div>
            <?php endif; ?>
            
            <div class="content">
                <div class="card">
                    <h2>📋 IP列表 (<?= count($ips) ?>)</h2>
                    <button class="copy-btn" onclick="copyAllIPs()">复制所有IP</button>
                    <div class="ip-list">
                        <?php foreach ($ips as $ipInfo): ?>
                            <div class="ip-item">
                                <span class="ip-address"><?= htmlspecialchars($ipInfo['ip']) ?></span>
                                <span class="badge"><?= count($ipInfo['devices']) ?> 设备</span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                
                <div class="card">
                    <h2>💻 设备列表 (<?= count($devices) ?>)</h2>
                    <div class="device-list">
                        <?php foreach ($devices as $device): ?>
                            <div class="device-item">
                                <div class="device-name">🖥️ <?= htmlspecialchars($device['hostname']) ?></div>
                                <div class="device-info">
                                    ID: <?= htmlspecialchars($device['device_id']) ?><br>
                                    IP数量: <?= $device['ip_count'] ?><br>
                                    最后上传: <?= htmlspecialchars($device['last_update']) ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
            
            <div class="card" style="margin-top: 20px;">
                <h2>🔗 API访问</h2>
                <div class="api-info">
                    <strong>📡 上传IP数据 (POST):</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST']) ?>/api/upload-ip</code><br><br>
                    
                    <strong>🔄 处理待处理文件:</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST']) ?>/api/process</code><br><br>
                    
                    <strong>📄 纯IP列表:</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST']) ?>/api/ips</code><br><br>
                    
                    <strong>📊 JSON数据:</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST']) ?>/api/json</code><br><br>
                    
                    <strong>📈 统计信息:</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST']) ?>/api/stats</code>
                </div>
                <button class="refresh-btn" onclick="location.reload()">🔄 刷新页面</button>
            </div>
        </div>
        
        <script>
            function copyAllIPs() {
                const ips = <?= json_encode(array_column($ips, 'ip')) ?>;
                const text = ips.join('\n');
                
                navigator.clipboard.writeText(text).then(() => {
                    alert('已复制 ' + ips.length + ' 个IP到剪贴板');
                }).catch(() => {
                    const textarea = document.createElement('textarea');
                    textarea.value = text;
                    document.body.appendChild(textarea);
                    textarea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textarea);
                    alert('已复制 ' + ips.length + ' 个IP到剪贴板');
                });
            }
            
            function processFiles() {
                if (!confirm('确定要处理所有待处理文件吗？')) return;
                
                fetch('<?= $_SERVER['PHP_SELF'] ?>?action=process')
                    .then(response => response.json())
                    .then(data => {
                        alert('处理完成！\n处理文件数: ' + data.processed);
                        location.reload();
                    })
                    .catch(error => {
                        alert('处理失败: ' + error);
                    });
            }
        </script>
    </body>
    </html>
    <?php
}

// ==================== 路由处理 ====================
$action = $_GET['action'] ?? ($_SERVER['REQUEST_METHOD'] === 'POST' ? 'upload' : 'web');

switch ($action) {
    case 'upload':
        handleUpload();
        break;
    
    case 'process':
        // 手动或定时处理上传文件
        $count = processUploadedFiles();
        header('Content-Type: application/json');
        echo json_encode([
            'success' => true,
            'processed' => $count,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        break;
    
    case 'list':
        getIPList();
        break;
    
    case 'stats':
        getStats();
        break;
    
    case 'merge':
        validateApiKey();
        $result = mergeAllIPs();
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'data' => $result]);
        break;
    
    case 'ips':
        header('Content-Type: text/plain; charset=utf-8');
        if (file_exists(SIMPLE_LIST)) {
            readfile(SIMPLE_LIST);
        } else {
            echo '';
        }
        break;
    
    case 'json':
        header('Content-Type: application/json; charset=utf-8');
        if (file_exists(MERGED_FILE)) {
            readfile(MERGED_FILE);
        } else {
            echo json_encode([
                'updated_at' => date('Y-m-d H:i:s'),
                'total_ips' => 0,
                'total_devices' => 0,
                'devices' => [],
                'ips' => []
            ]);
        }
        break;
    
    case 'web':
    default:
        showWebUI();
        break;
}
?>
