<?php
/**
 * ip_lib.php — IP 白名单共用库（index.php 与 api/process_ftp.php 共用）
 *
 * 只放函数，不输出任何内容。
 * 约定：
 *   - 客户端上报原始地址（IPv4 或 IPv6 /128）
 *   - 服务端校验后，IPv6 折叠成 /64 前缀再对外输出，IPv4 原样
 *   - merged_ips.json 的 ips[].addresses 保留 IPv6 原始地址，方便追溯
 */

if (!defined('IP_LIB_LOADED')) {
define('IP_LIB_LOADED', true);

// ---------- 常量（可在 include 之前 define 覆盖） ----------
if (!defined('IPV6_FOLD_LEN'))      define('IPV6_FOLD_LEN', 64);   // IPv6 折叠前缀长度
if (!defined('MAX_ADDR_PER_PREFIX')) define('MAX_ADDR_PER_PREFIX', 20);

// ---------- 日志（调用方可定义 ip_lib_log 覆盖） ----------
function ip_lib_log($msg) {
    if (function_exists('writeDebugLog')) { writeDebugLog($msg); return; }
    if (defined('LOG_FILE')) {
        @file_put_contents(LOG_FILE, '[' . date('Y-m-d H:i:s') . "] $msg\n", FILE_APPEND);
    }
}

// ==================== 地址校验 / 折叠 ====================

/**
 * 校验并规范化一个 IP。
 * 返回 ['family'=>4|6, 'ip'=>规范化原始地址, 'key'=>对外输出的值(v4=自身, v6=前缀/64)]；非法或非公网返回 null
 */
function normalize_ip($raw) {
    if (!is_string($raw)) return null;
    $raw = trim($raw);
    if ($raw === '' || strlen($raw) > 45) return null;
    if (!filter_var($raw, FILTER_VALIDATE_IP)) return null;

    $bin = @inet_pton($raw);
    if ($bin === false) return null;

    // IPv4-mapped IPv6 (::ffff:a.b.c.d) → 当作 IPv4
    if (strlen($bin) === 16 && substr($bin, 0, 12) === "\0\0\0\0\0\0\0\0\0\0\xff\xff") {
        $bin = substr($bin, 12);
        $raw = inet_ntop($bin);
    }

    if (strlen($bin) === 4) {
        // IPv4：排除私有/保留/组播
        if (!filter_var($raw, FILTER_VALIDATE_IP,
            FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return null;
        if (ord($bin[0]) >= 224) return null;           // 224/4 组播 + 240/4 保留
        return ['family' => 4, 'ip' => $raw, 'key' => $raw];
    }

    // IPv6：只接受全球单播 2000::/3（自动排除 ::1、fe80::/10、fc00::/7、ff00::/8 等）
    if ((ord($bin[0]) & 0xe0) !== 0x20) return null;
    $canon = inet_ntop($bin);
    return ['family' => 6, 'ip' => $canon, 'key' => fold_ipv6($bin) ];
}

/** 把 16 字节 IPv6 折叠成 "前缀::/N" */
function fold_ipv6($bin, $len = IPV6_FOLD_LEN) {
    $out = '';
    for ($i = 0; $i < 16; $i++) {
        $bits = $len - $i * 8;
        if ($bits >= 8)      $out .= $bin[$i];
        elseif ($bits > 0)   $out .= chr(ord($bin[$i]) & ((0xff << (8 - $bits)) & 0xff));
        else                 $out .= "\0";
    }
    return inet_ntop($out) . '/' . $len;
}

/** 排序用：把 "1.2.3.4" 或 "2409::/64" 转成可比较的二进制串 */
function ip_sort_key($key) {
    $addr = explode('/', $key)[0];
    $bin = @inet_pton($addr);
    return $bin === false ? $addr : $bin;
}

// ==================== 上传数据清洗 ====================

function clean_text($s, $max = 80) {
    if (!is_string($s)) return '';
    $s = preg_replace('/[\x00-\x1f\x7f]/', '', $s);
    $s = trim((string)$s);
    // 非法 UTF-8 会让 json_encode 失败，直接只保留可打印 ASCII
    if (!preg_match('//u', $s)) $s = preg_replace('/[^\x20-\x7e]/', '', $s);
    // 按字符（UTF-8）截断，不依赖 mbstring；非法 UTF-8 时退回按字节截断
    if (preg_match('/^.{0,' . (int)$max . '}/su', $s, $m)) return $m[0];
    return substr($s, 0, $max);
}

/** 清洗客户端上报的 os 信息；没有就返回 null */
function sanitize_os($os) {
    if (is_string($os)) $os = ['name' => $os];
    if (!is_array($os)) return null;

    $family = strtolower(clean_text($os['family'] ?? '', 16));
    if (!in_array($family, ['windows', 'linux', 'macos', 'bsd', 'other'], true)) {
        $family = $family === '' ? '' : 'other';
    }
    $id = strtolower(preg_replace('/[^a-z0-9._-]/i', '', (string)($os['id'] ?? '')));
    $out = [
        'family'  => $family,
        'id'      => substr($id, 0, 32),
        'name'    => clean_text($os['name'] ?? ''),
        'version' => clean_text($os['version'] ?? '', 40),
        'kernel'  => clean_text($os['kernel'] ?? '', 60),
        'arch'    => clean_text($os['arch'] ?? '', 20),
    ];
    if ($out['family'] === '' && $out['id'] === '' && $out['name'] === '') return null;
    return $out;
}

/**
 * 清洗一份设备上传数据。无效返回 null。
 * 非法 / 私有 IP 直接丢弃（同时避免脏数据进入 nginx 配置）。
 */
function sanitize_device_payload($data, &$dropped = 0) {
    $dropped = 0;
    if (!is_array($data) || !isset($data['device_id']) || !isset($data['ips']) || !is_array($data['ips'])) return null;

    $deviceId = substr(preg_replace('/[^a-zA-Z0-9_-]/', '', (string)$data['device_id']), 0, 80);
    if ($deviceId === '') return null;

    $ips = [];
    $now = date('Y-m-d H:i:s');
    foreach ($data['ips'] as $item) {
        $rawIp = is_array($item) ? ($item['ip'] ?? '') : $item;
        $seen  = is_array($item) ? ($item['last_seen'] ?? '') : '';
        $n = normalize_ip($rawIp);
        if (!$n) { $dropped++; continue; }
        if (!is_string($seen) || !preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $seen)) $seen = $now;
        // 同一地址保留最新时间
        if (!isset($ips[$n['ip']]) || $seen > $ips[$n['ip']]['last_seen']) {
            $ips[$n['ip']] = ['ip' => $n['ip'], 'last_seen' => $seen];
        }
    }

    $collected = (string)($data['collected_at'] ?? '');
    if (!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $collected)) $collected = $now;

    $out = [
        'device_id'    => $deviceId,
        'hostname'     => clean_text($data['hostname'] ?? 'unknown', 64) ?: 'unknown',
        'collected_at' => $collected,
        'received_at'  => $now,
        'ip_count'     => count($ips),
        'ips'          => array_values($ips),
    ];
    $os = sanitize_os($data['os'] ?? null);
    if ($os) $out['os'] = $os;
    return $out;
}

// ==================== 文件处理 / 合并 ====================

function write_atomic($path, $content) {
    $tmp = $path . '.tmp' . getmypid();
    if (file_put_contents($tmp, $content, LOCK_EX) === false) return false;
    return rename($tmp, $path);
}

/** 处理 UPLOAD_DIR 里待处理的 json，写入 DATA_DIR，然后合并。返回处理数量 */
function processUploadedFiles() {
    ip_lib_log('开始处理上传文件...');
    $ok = 0; $bad = 0;

    foreach (glob(UPLOAD_DIR . '/*.json') as $file) {
        $name = basename($file);
        $raw = @file_get_contents($file);
        $dropped = 0;
        $clean = sanitize_device_payload(json_decode((string)$raw, true), $dropped);
        if (!$clean) {
            ip_lib_log("  ✗ 文件格式无效: $name");
            @rename($file, $file . '.bad');   // 留着排查，不再反复处理
            $bad++;
            continue;
        }

        $target = DATA_DIR . '/' . $clean['device_id'] . '.json';

        // 旧版客户端不带 os：沿用服务器上已有的 os，避免被覆盖丢失
        if (!isset($clean['os']) && is_file($target)) {
            $old = json_decode((string)@file_get_contents($target), true);
            if (!empty($old['os'])) $clean['os'] = $old['os'];
        }

        write_atomic($target, json_encode($clean, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        @unlink($file);
        $ok++;
        ip_lib_log("  ✓ {$clean['device_id']}: " . count($clean['ips']) . " 个地址" . ($dropped ? "，丢弃无效 $dropped 个" : ''));
    }

    ip_lib_log("处理完成: 成功 $ok 个, 失败 $bad 个");
    if ($ok > 0) mergeAllIPs();
    return $ok;
}

/** 合并所有设备数据，生成 merged_ips.json 与各类纯文本列表 */
function mergeAllIPs() {
    $lock = @fopen(DATA_DIR . '/merge.lock', 'c');
    if ($lock) flock($lock, LOCK_EX);

    ip_lib_log('开始合并IP数据...');
    $entries = [];   // key => entry
    $devices = [];

    foreach (glob(DATA_DIR . '/*.json') as $file) {
        if (in_array(basename($file), ['merged_ips.json', 'rate_limits.json'], true)) continue;
        $d = json_decode((string)@file_get_contents($file), true);
        if (!is_array($d) || !isset($d['ips']) || !is_array($d['ips'])) continue;

        $id = $d['device_id'] ?? basename($file, '.json');
        $n4 = $n6 = 0;
        $devKeys = [];

        foreach ($d['ips'] as $item) {
            $n = normalize_ip(is_array($item) ? ($item['ip'] ?? '') : $item);
            if (!$n) continue;                                  // 历史脏数据在这里被挡掉
            $seen = is_array($item) ? (string)($item['last_seen'] ?? '') : '';
            $k = $n['key'];

            if (!isset($entries[$k])) {
                $entries[$k] = ['ip' => $k, 'family' => $n['family'], 'last_seen' => $seen, 'devices' => []];
                if ($n['family'] === 6) { $entries[$k]['prefix_len'] = IPV6_FOLD_LEN; $entries[$k]['addresses'] = []; }
            }
            if ($seen > $entries[$k]['last_seen']) $entries[$k]['last_seen'] = $seen;
            if (!in_array($id, $entries[$k]['devices'], true)) $entries[$k]['devices'][] = $id;
            if ($n['family'] === 6 && count($entries[$k]['addresses']) < MAX_ADDR_PER_PREFIX
                && !in_array($n['ip'], $entries[$k]['addresses'], true)) {
                $entries[$k]['addresses'][] = $n['ip'];
            }
            if (!isset($devKeys[$k])) { $devKeys[$k] = 1; $n['family'] === 4 ? $n4++ : $n6++; }
        }

        $devices[$id] = [
            'device_id'   => $id,
            'hostname'    => $d['hostname'] ?? 'unknown',
            'last_update' => $d['received_at'] ?? ($d['collected_at'] ?? ''),
            'collected_at'=> $d['collected_at'] ?? '',
            'ip_count'    => $n4 + $n6,
            'ip4_count'   => $n4,
            'ip6_count'   => $n6,
            'os'          => $d['os'] ?? null,
        ];
    }

    uksort($entries, function ($a, $b) { return strcmp(ip_sort_key($a), ip_sort_key($b)); });
    $all = array_values($entries);
    $v4 = array_values(array_filter($all, fn($e) => $e['family'] === 4));
    $v6 = array_values(array_filter($all, fn($e) => $e['family'] === 6));

    $merged = [
        'updated_at'    => date('Y-m-d H:i:s'),
        'total_ips'     => count($all),
        'total_ipv4'    => count($v4),
        'total_ipv6'    => count($v6),
        'total_devices' => count($devices),
        'devices'       => array_values($devices),
        'ips'           => $all,
    ];
    write_atomic(MERGED_FILE, json_encode($merged, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

    // 每行以换行结尾（否则 bash 的 while read 会丢掉最后一行）
    $lines = fn($list) => $list ? implode("\n", array_column($list, 'ip')) . "\n" : '';
    write_atomic(DATA_DIR . '/ip_list.txt',     $lines($v4));   // 旧版：仅 IPv4，老消费者不受影响
    write_atomic(DATA_DIR . '/ip_list4.txt',    $lines($v4));
    write_atomic(DATA_DIR . '/ip_list6.txt',    $lines($v6));
    write_atomic(DATA_DIR . '/ip_list_all.txt', $lines($all));

    ip_lib_log("合并完成: IPv4 " . count($v4) . " 个, IPv6 " . count($v6) . " 个前缀, 设备 " . count($devices) . " 个");
    if ($lock) { flock($lock, LOCK_UN); fclose($lock); }
    return $merged;
}

/** 读取 merged_ips.json，缺失时返回空结构 */
function load_merged() {
    $d = is_file(MERGED_FILE) ? json_decode((string)file_get_contents(MERGED_FILE), true) : null;
    if (!is_array($d)) {
        $d = ['updated_at' => null, 'total_ips' => 0, 'total_ipv4' => 0, 'total_ipv6' => 0,
              'total_devices' => 0, 'devices' => [], 'ips' => []];
    }
    return $d;
}

/** 按 family 过滤后的 JSON 结构；$family = 4 | 6 | 'all' */
function merged_view($family) {
    $d = load_merged();
    if ($family === 'all') return $d;

    $ips = array_values(array_filter($d['ips'] ?? [], fn($e) => (int)($e['family'] ?? 4) === $family));
    $ids = [];
    foreach ($ips as $e) foreach ($e['devices'] as $x) $ids[$x] = 1;
    $devs = array_values(array_filter($d['devices'] ?? [], fn($x) => isset($ids[$x['device_id']])));

    return [
        'updated_at'    => $d['updated_at'],
        'family'        => $family,
        'total_ips'     => count($ips),
        'total_devices' => count($devs),
        'devices'       => $devs,
        'ips'           => $ips,
    ];
}

/** 纯文本列表；$family = 4 | 6 | 'all' */
function plain_list($family) {
    $d = merged_view($family);
    return $d['ips'] ? implode("\n", array_column($d['ips'], 'ip')) . "\n" : '';
}

} // IP_LIB_LOADED
