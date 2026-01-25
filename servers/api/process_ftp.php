<?php

// 配置
define('FTP_UPLOAD_DIR', '/www/wwwroot/myip.xxxx.com/api/uploads');  // FTP上传目录
define('DATA_DIR', '/www/wwwroot/myip.xxxx.com/api/ip_data');        // 数据存储目录
define('MERGED_FILE', DATA_DIR . '/merged_ips.json');
define('SIMPLE_LIST', DATA_DIR . '/ip_list.txt');
define('LOG_FILE', DATA_DIR . '/processor.log');

if (!is_dir(FTP_UPLOAD_DIR)) {
    mkdir(FTP_UPLOAD_DIR, 0755, true);
}
if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}

function writeLog($message) {
    $timestamp = date('Y-m-d H:i:s');
    file_put_contents(LOG_FILE, "[{$timestamp}] {$message}\n", FILE_APPEND);
}

function processFTPFiles() {
    writeLog("开始处理FTP上传文件...");
    
    $uploadedFiles = glob(FTP_UPLOAD_DIR . '/*.json');
    $processedCount = 0;
    $errorCount = 0;
    
    foreach ($uploadedFiles as $file) {
        $filename = basename($file);
        writeLog("处理文件: {$filename}");
        
        try {
            $content = file_get_contents($file);
            $data = json_decode($content, true);
            
            if (!$data || !isset($data['device_id']) || !isset($data['ips'])) {
                writeLog("  ✗ 文件格式无效: {$filename}");
                $errorCount++;
                continue;
            }
            
            $deviceId = preg_replace('/[^a-zA-Z0-9_-]/', '', $data['device_id']);
            $targetFile = DATA_DIR . '/' . $deviceId . '.json';
            
            file_put_contents($targetFile, json_encode($data, JSON_PRETTY_PRINT));
            writeLog("  ✓ 已保存到: {$targetFile}");
            
            unlink($file);
            
            $processedCount++;
            
        } catch (Exception $e) {
            writeLog("  ✗ 处理失败: " . $e->getMessage());
            $errorCount++;
        }
    }
    
    writeLog("处理完成: 成功 {$processedCount} 个, 失败 {$errorCount} 个");
    
    if ($processedCount > 0) {
        mergeAllIPs();
    }
    
    return $processedCount;
}

function mergeAllIPs() {
    writeLog("开始合并IP数据...");
    
    $allIPs = [];
    $deviceData = [];
    
    $files = glob(DATA_DIR . '/*.json');
    foreach ($files as $file) {
        $basename = basename($file);
        if ($basename === 'merged_ips.json') {
            continue;
        }
        
        $content = file_get_contents($file);
        $data = json_decode($content, true);
        
        if (!$data || !isset($data['ips'])) {
            continue;
        }
        
        $deviceId = $data['device_id'] ?? basename($file, '.json');
        $deviceData[$deviceId] = [
            'device_id'   => $deviceId,
            'hostname'    => $data['hostname']    ?? 'unknown',
            'last_update'=> $data['collected_at'] ?? '',
            'ip_count'    => count($data['ips'])
        ];
        
        foreach ($data['ips'] as $ipInfo) {
            $ip       = $ipInfo['ip'];
            $lastSeen = $ipInfo['last_seen'] ?? '';
            
            if (!isset($allIPs[$ip]) || $lastSeen > $allIPs[$ip]['last_seen']) {
                $allIPs[$ip] = [
                    'ip'        => $ip,
                    'last_seen'=> $lastSeen,
                    'devices'  => []
                ];
            }
            
            if (!in_array($deviceId, $allIPs[$ip]['devices'])) {
                $allIPs[$ip]['devices'][] = $deviceId;
            }
        }
    }
    
    $merged = [
        'updated_at'     => date('Y-m-d H:i:s'),
        'total_ips'      => count($allIPs),
        'total_devices' => count($deviceData),
        'devices'        => array_values($deviceData),
        'ips'            => array_values($allIPs)
    ];
    
    file_put_contents(MERGED_FILE, json_encode($merged, JSON_PRETTY_PRINT));
    
    $simpleList = array_keys($allIPs);
    sort($simpleList);
    file_put_contents(SIMPLE_LIST, implode("\n", $simpleList));
    
    writeLog("合并完成: {$merged['total_ips']} 个IP, {$merged['total_devices']} 个设备");
    
    return $merged;
}

function cleanOldFiles($days = 30) {
    writeLog("清理 {$days} 天前的文件...");
    
    $cutoffTime   = time() - ($days * 86400);
    $cleanedCount = 0;
    
    $files = glob(FTP_UPLOAD_DIR . '/*');
    foreach ($files as $file) {
        if (filemtime($file) < $cutoffTime) {
            unlink($file);
            $cleanedCount++;
        }
    }
    
    writeLog("清理完成: 删除了 {$cleanedCount} 个旧文件");
    
    return $cleanedCount;
}

$mode = $_GET['mode'] ?? 'process';

switch ($mode) {
    case 'process':
        $count = processFTPFiles();
        echo json_encode([
            'success'   => true,
            'processed' => $count,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        break;
    
    case 'merge':
        $result = mergeAllIPs();
        echo json_encode([
            'success' => true,
            'data'    => $result
        ]);
        break;
    
    case 'clean':
        $days  = $_GET['days'] ?? 30;
        $count = cleanOldFiles($days);
        echo json_encode([
            'success' => true,
            'cleaned' => $count
        ]);
        break;
    
    case 'status':
        $uploadCount = count(glob(FTP_UPLOAD_DIR . '/*.json'));
        $deviceCount = count(glob(DATA_DIR . '/*.json')) - 1;
        
        echo json_encode([
            'pending_uploads' => $uploadCount,
            'total_devices'   => $deviceCount,
            'upload_dir'      => FTP_UPLOAD_DIR,
            'data_dir'        => DATA_DIR
        ]);
        break;
    
    default:
        echo json_encode(['error' => 'Unknown mode']);
        break;
}
