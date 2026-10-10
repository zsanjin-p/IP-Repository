<?php
/**
 * FTP 上传文件处理脚本（计划任务用）
 * 与 index.php 共用 ../ip_lib.php，保证 cron 触发的合并与网页触发的结果完全一致
 * （旧版这里自带一份合并逻辑，会把 merged_ips.json 写回旧格式）
 */
define('UPLOAD_DIR', __DIR__ . '/uploads');
define('DATA_DIR',   __DIR__ . '/ip_data');
define('MERGED_FILE', DATA_DIR . '/merged_ips.json');
define('LOG_FILE',   DATA_DIR . '/processor.log');

require_once __DIR__ . '/../ip_lib.php';

foreach ([UPLOAD_DIR, DATA_DIR] as $dir) {
    if (!is_dir($dir)) mkdir($dir, 0755, true);
}

$n = processUploadedFiles();
if (PHP_SAPI === 'cli') echo "processed: $n\n";
