<?php




// ==================== 配置 ====================
define('API_KEY', 'your_secret_api_key_here1');  // 与客户端脚本中的API_KEY一致
define('DATA_DIR', __DIR__ . '/api/ip_data');       // 数据存储目录
define('MERGED_FILE', DATA_DIR . '/merged_ips.json');
define('SIMPLE_LIST', DATA_DIR . '/ip_list.txt');
define('RATE_LIMIT_FILE', DATA_DIR . '/rate_limits.json');

// 限制配置
define('MAX_UPLOAD_SIZE', 1048576);             // 最大上传大小 1MB
define('RATE_LIMIT_WINDOW', 300);               // 频率限制窗口 5分钟
define('MAX_UPLOADS_PER_WINDOW', 10);           // 每个窗口最多上传次数
define('RATE_LIMIT_BY_IP', true);               // 按IP限制（true）或按设备ID限制（false）

if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET');
header('Access-Control-Allow-Headers: Content-Type, X-API-Key');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

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

function validateApiKey() {
    $headers = getallheaders();
    $apiKey = $headers['X-API-Key'] ?? $_GET['api_key'] ?? '';
    
    if ($apiKey !== API_KEY) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid API key', 'code' => 401]);
        exit;
    }
}

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

function handleUpload() {
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
        return;
    }
    
    $json = file_get_contents('php://input');
    $data = json_decode($json, true);
    
    if (!$data || !isset($data['device_id']) || !isset($data['ips'])) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid data format', 'code' => 400]);
        return;
    }
    
    $deviceId = preg_replace('/[^a-zA-Z0-9_-]/', '', $data['device_id']);
    $deviceFile = DATA_DIR . '/' . $deviceId . '.json';
    
    file_put_contents($deviceFile, json_encode($data, JSON_PRETTY_PRINT));
    
    mergeAllIPs();
    
    http_response_code(200);
    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'device_id' => $deviceId,
        'ip_count' => count($data['ips']),
        'message' => 'Data received and merged successfully'
    ]);
}

function mergeAllIPs() {
    $allIPs = [];
    $deviceData = [];
    
    $files = glob(DATA_DIR . '/*.json');
    foreach ($files as $file) {
        $basename = basename($file);
        if ($basename === 'merged_ips.json' || $basename === 'rate_limits.json') {
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
    
    return $merged;
}

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
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
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
            .copy-btn {
                background: #667eea;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 12px;
                transition: background 0.2s;
            }
            .copy-btn:hover {
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
                <div class="stat-card">
                    <h3>最后更新</h3>
                    <div class="value" style="font-size: 18px;"><?= htmlspecialchars($lastUpdate) ?></div>
                </div>
            </div>
            
            <div class="content">
                <div class="card">
                    <h2>📋 IP列表 (<?= count($ips) ?>)</h2>
                    <button class="copy-btn" onclick="copyAllIPs()">复制所有IP</button>
                    <div class="ip-list" id="ip-list">
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
                    <strong>Web界面 (浏览器访问):</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF']) ?></code><br><br>
                    
                    <strong>纯IP列表 (一行一个):</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF']) ?>?action=ips</code><br><br>
                    
                    <strong>纯JSON数据:</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF']) ?>?action=json</code><br><br>
                    
                    <strong>获取JSON格式 (兼容旧版):</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF']) ?>?action=list</code><br><br>
                    
                    <strong>获取TXT格式 (兼容旧版):</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF']) ?>?action=list&format=txt</code><br><br>
                    
                    <strong>获取统计信息:</strong><br>
                    <code><?= htmlspecialchars($_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF']) ?>?action=stats</code>
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
        </script>
    </body>
    </html>
    <?php
}

$action = $_GET['action'] ?? ($_SERVER['REQUEST_METHOD'] === 'POST' ? 'upload' : 'web');

switch ($action) {
    case 'upload':
        handleUpload();
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
