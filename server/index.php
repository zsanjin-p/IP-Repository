<?php
/**
 * IP收集整合API v2（IPv4 + IPv6 / 设备系统图标 / 分族接口）
 *
 * 上传：HTTP/FTP → /api/uploads/ → 校验清洗 → /api/ip_data/<device>.json → 合并
 * IPv6：服务端统一折叠成 /64 前缀输出，merged_ips.json 的 addresses 里保留原始地址
 *
 * 接口（纯文本 / JSON）：
 *   /api/ips4   /api/json4     仅 IPv4
 *   /api/ips6   /api/json6     仅 IPv6（/64 前缀）
 *   /api/ips-all /api/json-all IPv4 + IPv6
 *   /api/ips    /api/json      兼容旧接口，仅 IPv4（老消费者不受影响）
 */

require_once __DIR__ . '/ip_lib.php';

// ==================== 配置 ====================
define('API_KEY', 'your_secret_api_key_here135');
define('UPLOAD_DIR', __DIR__ . '/api/uploads');
define('DATA_DIR', __DIR__ . '/api/ip_data');
define('MERGED_FILE', DATA_DIR . '/merged_ips.json');
define('RATE_LIMIT_FILE', DATA_DIR . '/rate_limits.json');
define('DEBUG_LOG', DATA_DIR . '/api_debug.log');

define('MAX_UPLOAD_SIZE', 1048576);
define('RATE_LIMIT_WINDOW', 300);
define('MAX_UPLOADS_PER_WINDOW', 10);
define('RATE_LIMIT_BY_IP', true);

// ==================== 路由 ====================
// 精确匹配（旧版用前缀匹配，/api/ips4 会被 /api/ips 误吞）
$pathRoutes = [
    '/api/upload-ip' => 'upload',
    '/api/upload'    => 'upload',
    '/api/list'      => 'list',
    '/api/stats'     => 'stats',
    '/api/merge'     => 'merge',
    '/api/process'   => 'process',
    '/api/ips'       => 'ips',       // 兼容：仅 IPv4
    '/api/json'      => 'json',      // 兼容：仅 IPv4
    '/api/ips4'      => 'ips4',
    '/api/ips6'      => 'ips6',
    '/api/ips-all'   => 'ipsall',
    '/api/json4'     => 'json4',
    '/api/json6'     => 'json6',
    '/api/json-all'  => 'jsonall',
];
$requestUri = rtrim((string)parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH), '/');
if (isset($pathRoutes[$requestUri])) {
    $_GET['action'] = $pathRoutes[$requestUri];
}

foreach ([UPLOAD_DIR, DATA_DIR] as $dir) {
    if (!is_dir($dir)) mkdir($dir, 0755, true);
}

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET');
header('Access-Control-Allow-Headers: Content-Type, X-API-Key');
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') { http_response_code(200); exit; }

// ==================== 工具函数 ====================
function writeDebugLog($message) {
    @file_put_contents(DEBUG_LOG, '[' . date('Y-m-d H:i:s') . "] $message\n", FILE_APPEND);
}

function getClientIP() {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (strpos($ip, ',') !== false) $ip = trim(explode(',', $ip)[0]);
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
        $rateLimits[$id] = array_values(array_filter($timestamps, fn($ts) => $ts > $windowStart));
        if (empty($rateLimits[$id])) unset($rateLimits[$id]);
    }
    if (count($rateLimits[$identifier] ?? []) >= MAX_UPLOADS_PER_WINDOW) return false;
    $rateLimits[$identifier][] = $now;
    file_put_contents(RATE_LIMIT_FILE, json_encode($rateLimits));
    return true;
}

function jsonOut($data, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

function validateApiKey() {
    $apiKey = '';
    foreach (function_exists('getallheaders') ? getallheaders() : [] as $name => $value) {
        if (strtolower($name) === 'x-api-key') { $apiKey = $value; break; }
    }
    if ($apiKey === '') $apiKey = $_SERVER['HTTP_X_API_KEY'] ?? ($_GET['api_key'] ?? '');

    // 日志只记结果，不再记录收到的密钥内容
    $ok = hash_equals(API_KEY, (string)$apiKey);
    writeDebugLog('API Key验证: ' . ($ok ? 'OK' : 'FAIL') . ' client=' . getClientIP() . ' uri=' . ($_SERVER['REQUEST_URI'] ?? ''));
    if (!$ok) {
        jsonOut(['error' => 'Invalid API key', 'code' => 401], 401);
        exit;
    }
}

function checkUploadSize() {
    $len = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($len > MAX_UPLOAD_SIZE) {
        jsonOut(['error' => 'Upload size exceeds limit', 'max_size' => MAX_UPLOAD_SIZE, 'code' => 413], 413);
        exit;
    }
}

// ==================== 上传 ====================
function handleUpload() {
    writeDebugLog('========== 新的HTTP上传请求 ==========');
    validateApiKey();
    checkUploadSize();

    $identifier = RATE_LIMIT_BY_IP ? getClientIP() : ($_POST['device_id'] ?? 'unknown');
    if (!checkRateLimit($identifier)) {
        writeDebugLog("✗ 频率限制: $identifier");
        jsonOut(['error' => 'Rate limit exceeded',
                 'limit' => MAX_UPLOADS_PER_WINDOW . ' uploads per ' . (RATE_LIMIT_WINDOW / 60) . ' minutes',
                 'code' => 429], 429);
        return;
    }

    $data = json_decode((string)file_get_contents('php://input'), true);
    $dropped = 0;
    $clean = sanitize_device_payload($data, $dropped);
    if (!$clean) {
        writeDebugLog('✗ 数据格式错误');
        jsonOut(['error' => 'Invalid data format', 'code' => 400], 400);
        return;
    }
    if (!$clean['ips']) {
        writeDebugLog("✗ {$clean['device_id']} 上传的地址全部无效");
        jsonOut(['error' => 'No valid public IP in payload', 'dropped' => $dropped, 'code' => 400], 400);
        return;
    }

    file_put_contents(UPLOAD_DIR . '/' . $clean['device_id'] . '.json',
        json_encode($clean, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    // os 缺失时的沿用逻辑在 processUploadedFiles() 里统一处理
    $processed = processUploadedFiles();

    jsonOut([
        'success'   => true,
        'device_id' => $clean['device_id'],
        'ip_count'  => count($clean['ips']),
        'dropped'   => $dropped,
        'processed' => $processed,
        'message'   => 'Data uploaded and processed successfully',
    ]);
    writeDebugLog('✓✓✓ HTTP上传成功完成');
}

// ==================== 读取接口 ====================
function outPlain($family) {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo plain_list($family);
}

function getStats() {
    $d = load_merged();
    jsonOut([
        'total_ips'     => $d['total_ips'] ?? 0,
        'total_ipv4'    => $d['total_ipv4'] ?? 0,
        'total_ipv6'    => $d['total_ipv6'] ?? 0,
        'total_devices' => $d['total_devices'] ?? 0,
        'last_update'   => $d['updated_at'] ?? null,
        'devices'       => $d['devices'] ?? [],
    ]);
}

// ==================== Web 界面 ====================
function showWebUI() {
    $d = load_merged();
    $pending = count(glob(UPLOAD_DIR . '/*.json') ?: []);
    $now = time();

    $devices = array_map(function ($x) use ($now) {
        $t = strtotime($x['last_update'] ?? '');
        $x['age'] = $t ? max(0, $now - $t) : null;
        return $x;
    }, $d['devices'] ?? []);
    // 最近上传的设备排前面
    usort($devices, fn($a, $b) => ($a['age'] ?? PHP_INT_MAX) <=> ($b['age'] ?? PHP_INT_MAX));

    $ua = $d['updated_at'] ?? null;
    $payload = [
        'devices' => $devices,
        'ips'     => $d['ips'] ?? [],
        'updated' => $ua,
        'updatedAge' => $ua && strtotime($ua) ? max(0, $now - strtotime($ua)) : null,
        'pending' => $pending,
    ];
    $flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE;

    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $base = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
    $endpoints = [
        ['IPv4',          '纯文本', '/api/ips4'],
        ['IPv4',          'JSON',   '/api/json4'],
        ['IPv6 (/64)',    '纯文本', '/api/ips6'],
        ['IPv6 (/64)',    'JSON',   '/api/json6'],
        ['IPv4 + IPv6',   '纯文本', '/api/ips-all'],
        ['IPv4 + IPv6',   'JSON',   '/api/json-all'],
        ['兼容旧接口（仅 IPv4）', '纯文本', '/api/ips'],
        ['兼容旧接口（仅 IPv4）', 'JSON',   '/api/json'],
    ];
    ?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP 白名单中心</title>
<style>
:root{
  --bg:#f4f5fb; --bg2:#e9ebf8; --card:#fff; --text:#1d2033; --muted:#6b7089; --line:#e6e8f2;
  --accent:#4f46e5; --accent-soft:#eceafd; --ok:#16a34a; --warn:#d97706; --stale:#9ca3af;
  --sb:rgba(100,106,140,.35); --sb-h:rgba(100,106,140,.6);
  --v4:#2563eb; --v4-soft:#e6efff; --v6:#7c3aed; --v6-soft:#f0e8ff; --shadow:0 1px 2px rgba(20,24,60,.06),0 6px 20px rgba(20,24,60,.05);
}
@media (prefers-color-scheme:dark){
  :root{ --bg:#0f1220; --bg2:#151932; --card:#181c33; --text:#e8eaf6; --muted:#8e94b5; --line:#262b4a;
    --accent:#8b83ff; --accent-soft:#272553; --sb:rgba(160,166,210,.28); --sb-h:rgba(160,166,210,.55); --v4:#6aa3ff; --v4-soft:#16264a; --v6:#b794ff; --v6-soft:#2a1f4d; --shadow:none; }
}
*{box-sizing:border-box;margin:0;padding:0}
:root{color-scheme:light dark}
/* 细滚动条，跟随主题；默认很淡，鼠标移上去才明显 */
*{scrollbar-width:thin;scrollbar-color:var(--sb) transparent}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--sb);border-radius:10px;border:3px solid transparent;background-clip:padding-box}
::-webkit-scrollbar-thumb:hover{background:var(--sb-h);background-clip:padding-box}
::-webkit-scrollbar-corner{background:transparent}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",Roboto,sans-serif;
  background:linear-gradient(180deg,var(--bg2),var(--bg) 320px) no-repeat,var(--bg);color:var(--text);min-height:100vh;padding:24px 16px 48px}
.wrap{max-width:1180px;margin:0 auto}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:22px;font-weight:700;letter-spacing:.2px}
h1 small{display:block;font-size:13px;font-weight:400;color:var(--muted);margin-top:4px}
.pill{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:999px;background:var(--card);border:1px solid var(--line);font-size:13px;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);display:inline-block}
.dot.warn{background:var(--warn)} .dot.stale{background:var(--stale)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;box-shadow:var(--shadow)}
.stat .k{font-size:12px;color:var(--muted);margin-bottom:6px}
.stat .v{font-size:30px;font-weight:700;line-height:1.1}
.stat.v4 .v{color:var(--v4)} .stat.v6 .v{color:var(--v6)}
.stat .s{font-size:12px;color:var(--muted);margin-top:4px}
.grid{display:grid;grid-template-columns:minmax(0,5fr) minmax(0,7fr);gap:16px;align-items:stretch}
/* 左右两张卡片等高：行高由「设备」卡片的内容决定（至少 460px，最高 760px），
   「地址列表」卡片绝对定位铺满同一行，内容多了只在它自己里面滚动 */
@media(min-width:901px){.grid{grid-template-rows:minmax(460px,auto)}}
.dev-card{display:flex;flex-direction:column;max-height:760px;min-height:0}
.dev-card>.body{flex:1;min-height:0}
.ip-wrap{position:relative;min-height:0}
.ip-card{position:absolute;inset:0;display:flex;flex-direction:column}
.ip-card>.body{flex:1;min-height:0}
@media(max-width:900px){.grid{grid-template-columns:1fr}.ip-wrap{height:560px}}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);overflow:hidden}
.card>h2{font-size:15px;font-weight:600;padding:14px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:8px}
.card>h2 .n{font-weight:400;color:var(--muted);font-size:13px}
.body{padding:12px 14px;overflow:auto}
.dev{display:flex;gap:12px;align-items:center;padding:10px;border-radius:10px}
.dev:hover{background:var(--accent-soft)}
.os{width:36px;height:36px;flex:none}
.os-sm{width:15px;height:15px;flex:none}
.dev .nm{font-weight:600;font-size:14px;display:flex;align-items:center;gap:8px}
.dev .sub{font-size:12px;color:var(--muted);margin-top:2px;line-height:1.5;word-break:break-all}
.tag{font-size:11px;padding:1px 7px;border-radius:999px;font-weight:500}
.tag.v4{background:var(--v4-soft);color:var(--v4)} .tag.v6{background:var(--v6-soft);color:var(--v6)}
.tools{display:flex;gap:8px;flex-wrap:wrap;padding:12px 14px;border-bottom:1px solid var(--line);align-items:center}
.tabs{display:inline-flex;background:var(--bg);border-radius:10px;padding:3px}
.tabs button{border:0;background:none;color:var(--muted);padding:6px 12px;border-radius:8px;font-size:13px;cursor:pointer}
.tabs button.on{background:var(--card);color:var(--text);box-shadow:var(--shadow);font-weight:600}
input[type=search]{flex:1;min-width:120px;border:1px solid var(--line);background:var(--bg);color:var(--text);border-radius:10px;padding:8px 12px;font-size:13px;outline:none}
input[type=search]:focus{border-color:var(--accent)}
.btn{border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:10px;padding:7px 12px;font-size:13px;cursor:pointer}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{opacity:.9;color:#fff}
.row{display:flex;align-items:center;gap:10px;padding:9px 8px;border-bottom:1px dashed var(--line);font-size:13px}
.row:last-child{border-bottom:0}
.row .ip{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;font-weight:600;word-break:break-all}
.row .meta{margin-left:auto;display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px;flex:none}
.chips{display:flex;gap:4px}
.chip{display:inline-flex;align-items:center;gap:4px;font-size:11px;color:var(--muted);background:var(--bg);border:1px solid var(--line);padding:2px 6px;border-radius:999px;max-width:110px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.copy{border:0;background:none;color:var(--muted);cursor:pointer;font-size:12px;padding:2px 6px;border-radius:6px}
.copy:hover{background:var(--accent-soft);color:var(--accent)}
.empty{padding:28px;text-align:center;color:var(--muted);font-size:13px}
.api{margin-top:16px}
.api table{width:100%;border-collapse:collapse;font-size:13px}
.api td{padding:9px 14px;border-bottom:1px solid var(--line);vertical-align:middle}
.api tr:last-child td{border-bottom:0}
.api code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--accent);word-break:break-all}
.api .g{color:var(--muted);white-space:nowrap}
.note{font-size:12px;color:var(--muted);padding:10px 14px;border-top:1px solid var(--line);line-height:1.6}
.alert{margin-bottom:16px;padding:12px 16px;border-radius:12px;background:#fff7e6;border:1px solid #f5c26b;color:#7a4b00;display:flex;gap:12px;align-items:center;justify-content:space-between;font-size:14px}
.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(20px);background:#111;color:#fff;padding:9px 16px;border-radius:10px;font-size:13px;opacity:0;pointer-events:none;transition:.2s}
.toast.show{opacity:1;transform:translateX(-50%)}
</style>
</head>
<body>

<!-- 系统图标 -->
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <symbol id="i-windows" viewBox="0 0 24 24"><path fill="#0a7ad8" d="M1 3.6 10.2 2.3v8.6H1zM11.4 2.1 23 .4v10.5H11.4zM1 12.1h9.2v8.6L1 19.4zM11.4 12.1H23v11.5l-11.6-1.7z"/></symbol>
  <symbol id="i-ubuntu" viewBox="0 0 24 24"><circle cx="12" cy="12" r="11.5" fill="#e95420"/><circle cx="12" cy="12" r="6.2" fill="none" stroke="#fff" stroke-width="1.9"/><g fill="#fff" stroke="#e95420" stroke-width="1.1"><circle cx="5.7" cy="12" r="2.2"/><circle cx="15.1" cy="6.6" r="2.2"/><circle cx="15.1" cy="17.4" r="2.2"/></g></symbol>
  <symbol id="i-debian" viewBox="0 0 24 24"><circle cx="12" cy="12" r="11.5" fill="#a80030"/><path d="M12.6 5.4c-3.9-.5-7 2.4-6.7 6 .3 3.6 3.6 6 7 5.3 2.7-.6 4.1-3.4 3.1-5.6-.9-1.9-3.4-2.4-4.7-1-.9 1-.5 2.6.7 3" fill="none" stroke="#fff" stroke-width="1.7" stroke-linecap="round"/></symbol>
  <symbol id="i-linux" viewBox="0 0 24 24"><ellipse cx="12" cy="14" rx="6.3" ry="8.2" fill="#232733"/><ellipse cx="12" cy="15.4" rx="3.7" ry="5.4" fill="#f4f4f4"/><circle cx="12" cy="7" r="4.3" fill="#232733"/><circle cx="10.5" cy="6.4" r="1.15" fill="#fff"/><circle cx="13.5" cy="6.4" r="1.15" fill="#fff"/><circle cx="10.7" cy="6.5" r=".5" fill="#232733"/><circle cx="13.3" cy="6.5" r=".5" fill="#232733"/><ellipse cx="12" cy="8.5" rx="1.9" ry="1" fill="#f6b926"/><ellipse cx="8.2" cy="21.6" rx="2.7" ry="1.2" fill="#f6b926"/><ellipse cx="15.8" cy="21.6" rx="2.7" ry="1.2" fill="#f6b926"/></symbol>
  <symbol id="i-unknown" viewBox="0 0 24 24"><rect x="2.5" y="4" width="19" height="13" rx="2" fill="none" stroke="#8e94b5" stroke-width="1.7"/><path d="M8 21h8M12 17v4" stroke="#8e94b5" stroke-width="1.7" stroke-linecap="round"/></symbol>
</svg>

<div class="wrap">
  <header>
    <h1>🌐 IP 白名单中心<small>设备上报的公网地址，IPv6 按 /64 前缀统一输出</small></h1>
    <span class="pill" id="updatedPill"><span class="dot" id="updatedDot"></span><span id="updatedText"></span></span>
  </header>

  <?php if ($pending > 0): ?>
  <div class="alert"><span>⚠️ 有 <?= (int)$pending ?> 个上传文件等待处理</span><button class="btn primary" onclick="processFiles()">立即处理</button></div>
  <?php endif; ?>

  <section class="stats">
    <div class="stat"><div class="k">地址总数</div><div class="v" id="sTotal">0</div><div class="s">IPv4 + IPv6 前缀</div></div>
    <div class="stat v4"><div class="k">IPv4</div><div class="v" id="sV4">0</div><div class="s">单个地址</div></div>
    <div class="stat v6"><div class="k">IPv6</div><div class="v" id="sV6">0</div><div class="s">/<?= (int)IPV6_FOLD_LEN ?> 前缀</div></div>
    <div class="stat"><div class="k">设备</div><div class="v" id="sDev">0</div><div class="s" id="sDevSub"></div></div>
  </section>

  <div class="grid">
    <div class="card dev-card">
      <h2>设备 <span class="n" id="devCount"></span></h2>
      <div class="body" id="devList"></div>
    </div>

    <div class="ip-wrap"><div class="card ip-card">
      <h2>地址列表 <span class="n" id="ipCount"></span></h2>
      <div class="tools">
        <div class="tabs" id="tabs">
          <button data-f="all" class="on">全部</button>
          <button data-f="4">IPv4</button>
          <button data-f="6">IPv6</button>
        </div>
        <input type="search" id="q" placeholder="搜索地址或设备名">
        <button class="btn" onclick="copyList()">复制当前列表</button>
      </div>
      <div class="body" id="ipList"></div>
    </div></div>
  </div>

  <div class="card api">
    <h2>接口</h2>
    <table>
      <?php foreach ($endpoints as [$grp, $kind, $path]): ?>
      <tr>
        <td class="g"><?= htmlspecialchars($grp) ?></td>
        <td class="g"><?= $kind ?></td>
        <td><code><?= htmlspecialchars($base . $path) ?></code></td>
        <td style="text-align:right"><button class="copy" data-copy="<?= htmlspecialchars($base . $path) ?>">复制</button></td>
      </tr>
      <?php endforeach; ?>
    </table>
    <div class="note">
      兼容旧接口 <code>/api/ips</code>、<code>/api/json</code> 仍只返回 IPv4，没升级的使用端不受影响。
      上传：<code>POST <?= htmlspecialchars($base) ?>/api/upload-ip</code>（需 X-API-Key）　统计：<code>/api/stats</code>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const D = <?= json_encode($payload, $flags) ?>;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function osKey(os){
  if(!os) return 'unknown';
  const id=(os.id||'').toLowerCase(), fam=(os.family||'').toLowerCase(), nm=(os.name||'').toLowerCase();
  if(fam==='windows'||nm.includes('windows')) return 'windows';
  if(id==='ubuntu') return 'ubuntu';
  if(id==='debian') return 'debian';
  if(fam==='linux') return 'linux';
  return 'unknown';
}
const icon = (os, cls) => `<svg class="${cls}"><use href="#i-${osKey(os)}"/></svg>`;

function ago(sec){
  if(sec==null) return '未知';
  if(sec<60) return '刚刚';
  if(sec<3600) return Math.floor(sec/60)+' 分钟前';
  if(sec<86400) return Math.floor(sec/3600)+' 小时前';
  return Math.floor(sec/86400)+' 天前';
}
const staleCls = sec => sec==null ? 'stale' : sec>14*86400 ? 'stale' : sec>2*86400 ? 'warn' : '';

const devMap = Object.fromEntries(D.devices.map(d => [d.device_id, d]));
const v4n = D.ips.filter(e=>e.family==4).length, v6n = D.ips.filter(e=>e.family==6).length;

// 顶部
$('#sTotal').textContent = D.ips.length; $('#sV4').textContent = v4n; $('#sV6').textContent = v6n;
$('#sDev').textContent = D.devices.length;
const recent = D.devices.filter(d => d.age!=null && d.age<=2*86400).length;
$('#sDevSub').textContent = recent + ' 台近 2 天有上报';
$('#updatedText').textContent = '最后更新 ' + ago(D.updatedAge);
$('#updatedDot').className = 'dot ' + staleCls(D.updatedAge);

// 设备
$('#devCount').textContent = D.devices.length;
$('#devList').innerHTML = D.devices.length ? D.devices.map(d => {
  const o = d.os, osName = o && (o.name || o.id) || '系统未上报';
  const detail = [o && o.version, o && o.arch].filter(Boolean).join(' · ');
  return `<div class="dev">${icon(o,'os')}<div style="min-width:0">
    <div class="nm">${esc(d.hostname)}<span class="dot ${staleCls(d.age)}" title="最后上传 ${esc(d.last_update)}"></span></div>
    <div class="sub">${esc(osName)}${detail?' · '+esc(detail):''}</div>
    <div class="sub">${d.ip4_count?`<span class="tag v4">IPv4 ${d.ip4_count}</span> `:''}${d.ip6_count?`<span class="tag v6">IPv6 ${d.ip6_count}</span> `:''}${ago(d.age)}上报 · ${esc(d.device_id)}</div>
  </div></div>`;
}).join('') : '<div class="empty">还没有设备上报</div>';

// 地址
let fam = 'all';
function filtered(){
  const q = $('#q').value.trim().toLowerCase();
  return D.ips.filter(e => {
    if(fam!=='all' && e.family!=fam) return false;
    if(!q) return true;
    if(e.ip.toLowerCase().includes(q)) return true;
    return e.devices.some(id => ((devMap[id]||{}).hostname||id).toLowerCase().includes(q));
  });
}
function renderIPs(){
  const list = filtered();
  $('#ipCount').textContent = list.length + ' 条';
  $('#ipList').innerHTML = list.length ? list.map(e => {
    const chips = e.devices.map(id => { const d=devMap[id]||{}; return `<span class="chip" title="${esc(id)}">${icon(d.os,'os-sm')}${esc(d.hostname||id)}</span>`; }).join('');
    const addrs = e.family==6 && e.addresses && e.addresses.length ? ` title="包含 ${e.addresses.length} 个原始地址：\n${esc(e.addresses.join('\n'))}"` : '';
    return `<div class="row"><span class="tag v${e.family}">v${e.family}</span><span class="ip"${addrs}>${esc(e.ip)}</span>
      <span class="meta"><span class="chips">${chips}</span><span>${esc((e.last_seen||'').slice(5,16))}</span><button class="copy" data-copy="${esc(e.ip)}">复制</button></span></div>`;
  }).join('') : '<div class="empty">没有匹配的地址</div>';
}
$('#tabs').addEventListener('click', ev => {
  const b = ev.target.closest('button'); if(!b) return;
  fam = b.dataset.f; document.querySelectorAll('#tabs button').forEach(x => x.classList.toggle('on', x===b)); renderIPs();
});
$('#q').addEventListener('input', renderIPs);
renderIPs();

// 复制
function toast(t){ const el=$('#toast'); el.textContent=t; el.classList.add('show'); setTimeout(()=>el.classList.remove('show'),1600); }
function copyText(text, msg){
  const done = () => toast(msg||'已复制');
  if(navigator.clipboard && window.isSecureContext){ navigator.clipboard.writeText(text).then(done, fallback); } else fallback();
  function fallback(){ const t=document.createElement('textarea'); t.value=text; document.body.appendChild(t); t.select(); document.execCommand('copy'); t.remove(); done(); }
}
function copyList(){ const l=filtered().map(e=>e.ip); copyText(l.join('\n'), '已复制 '+l.length+' 条'); }
document.addEventListener('click', ev => { const b=ev.target.closest('[data-copy]'); if(b) copyText(b.dataset.copy); });

function processFiles(){
  if(!confirm('确定要处理所有待处理文件吗？')) return;
  fetch('/api/process').then(r=>r.json()).then(r=>{ toast('已处理 '+r.processed+' 个文件'); setTimeout(()=>location.reload(),800); })
    .catch(e=>alert('处理失败: '+e));
}
</script>
</body>
</html>
    <?php
}

// ==================== 路由分发 ====================
$action = $_GET['action'] ?? (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' ? 'upload' : 'web');

switch ($action) {
    case 'upload':  handleUpload(); break;
    case 'process':
        $count = processUploadedFiles();
        jsonOut(['success' => true, 'processed' => $count, 'timestamp' => date('Y-m-d H:i:s')]);
        break;
    case 'merge':
        validateApiKey();
        jsonOut(['success' => true, 'data' => mergeAllIPs()]);
        break;
    case 'stats':   getStats(); break;
    case 'list':    // 旧接口 ?format=txt|json
        if (($_GET['format'] ?? 'json') === 'txt') outPlain(4); else jsonOut(merged_view(4));
        break;
    case 'ips':     outPlain(4); break;         // 兼容：仅 IPv4
    case 'ips4':    outPlain(4); break;
    case 'ips6':    outPlain(6); break;
    case 'ipsall':  outPlain('all'); break;
    case 'json':    jsonOut(merged_view(4)); break;   // 兼容：仅 IPv4（结构与旧版一致）
    case 'json4':   jsonOut(merged_view(4)); break;
    case 'json6':   jsonOut(merged_view(6)); break;
    case 'jsonall': jsonOut(merged_view('all')); break;
    case 'web':
    default:        showWebUI(); break;
}
