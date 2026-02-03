#!/bin/bash

# 配置信息
UPLOAD_URL="https://****.com/api/upload-ip"
API_KEY="****"

UPLOAD_METHOD="ftp"

FTP_HOST="1.2.3.4"
FTP_PORT=21
FTP_USER="user"
FTP_PASS="****"
FTP_UPLOAD_DIR="/api/uploads"

WORK_DIR="/root/myiplist"
IP_HISTORY_FILE="$WORK_DIR/ip_history.txt"
IP_EXPORT_SIMPLE="$WORK_DIR/ip_list.txt"
IP_EXPORT_JSON="$WORK_DIR/ip_data.json"
LOG_FILE="$WORK_DIR/collector.log"
DEVICE_ID_FILE="$WORK_DIR/device_id.txt"


MAX_HISTORY_SIZE=100

IP_SERVICES=(
    "http://ip.3322.net"
    "http://members.3322.org/dyndns/getip"
    "http://pv.sohu.com/cityjson?ie=utf-8"
    "http://myip.ipip.net"
    "http://ip.chinaz.com/getip.aspx"
    "http://www.ip.cn/api/index?ip=&type=0"
    "http://ip.cip.cc"
    "http://ifconfig.me"
    "http://api.ipify.org"
    "http://icanhazip.com"
    "http://ddns.oray.com/checkip"
    "https://api.ipify.org"
    "https://ifconfig.me"
    "https://icanhazip.com"
)

MAX_RETRIES=3
RETRY_DELAY=5

# 写入日志函数（只写入LOG_FILE）
write_log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$LOG_FILE"
}

init_workdir() {
    if [ ! -d "$WORK_DIR" ]; then
        mkdir -p "$WORK_DIR"
        write_log "创建工作目录: $WORK_DIR"
    fi
    
    if [ ! -f "$IP_HISTORY_FILE" ]; then
        touch "$IP_HISTORY_FILE"
    fi
}

get_device_id() {
    if [ -f "$DEVICE_ID_FILE" ]; then
        cat "$DEVICE_ID_FILE"
        return
    fi
    
    local hostname=$(hostname 2>/dev/null || echo "unknown")
    local random_id=$(printf "%05d" $((RANDOM % 100000)))
    local device_id="${hostname}-${random_id}"
    
    echo "$device_id" > "$DEVICE_ID_FILE"
    write_log "生成设备ID: $device_id"
    
    echo "$device_id"
}

parse_sohu_ip() {
    local response="$1"
    local ip=$(echo "$response" | grep -oP '(?<="cip": ")[^"]+' 2>/dev/null)
    if [ -z "$ip" ]; then
        ip=$(echo "$response" | grep -oP '(?<=cip":")[^"]+' 2>/dev/null)
    fi
    echo "$ip"
}

parse_ipip_ip() {
    local response="$1"
    local ip=$(echo "$response" | grep -oP '(?<=IP：|IP:)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    if [ -z "$ip" ]; then
        ip=$(echo "$response" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    fi
    echo "$ip"
}

parse_ipcn_ip() {
    local response="$1"
    local ip=$(echo "$response" | grep -oP '(?<="ip":")[^"]+' 2>/dev/null)
    if [ -z "$ip" ]; then
        ip=$(echo "$response" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    fi
    echo "$ip"
}

validate_ip() {
    local ip="$1"
    
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    IFS='.' read -ra OCTETS <<< "$ip"
    for octet in "${OCTETS[@]}"; do
        if [ "$octet" -gt 255 ]; then
            return 1
        fi
    done
    
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.) ]]; then
        return 1
    fi
    
    if [[ "$ip" =~ ^(0\.|169\.254\.|224\.|240\.) ]]; then
        return 1
    fi
    
    return 0
}

get_ip_from_service() {
    local service="$1"
    local timeout="${2:-5}"
    
    write_log "→ 尝试: $service"
    
    local response=$(curl -s --max-time "$timeout" --connect-timeout 3 "$service" 2>&1)
    local curl_exit_code=$?
    
    if [ $curl_exit_code -ne 0 ]; then
        write_log "  ✗ 连接失败"
        return 1
    fi
    
    if [ -z "$response" ]; then
        write_log "  ✗ 响应为空"
        return 1
    fi
    
    local ip=""
    case "$service" in
        *sohu.com*)
            ip=$(parse_sohu_ip "$response")
            ;;
        *ipip.net*)
            ip=$(parse_ipip_ip "$response")
            ;;
        *ip.cn*)
            ip=$(parse_ipcn_ip "$response")
            ;;
        *)
            ip=$(echo "$response" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
            ;;
    esac
    
    if [ -z "$ip" ]; then
        write_log "  ✗ 无法解析IP"
        return 1
    fi
    
    if validate_ip "$ip"; then
        write_log "  ✓ 检测到IP: $ip"
        echo "$ip"
        return 0
    else
        write_log "  ✗ IP验证失败: $ip"
        return 1
    fi
}

get_current_ips() {
    local retry_count=0
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        if [ $retry_count -gt 0 ]; then
            write_log "⟳ 第 $((retry_count + 1)) 次尝试..."
            sleep $RETRY_DELAY
        else
            write_log "开始检测公网IP..."
        fi
        
        local detected_ips=()
        
        for service in "${IP_SERVICES[@]}"; do
            ip=$(get_ip_from_service "$service" 5)
            if [ $? -eq 0 ] && [ -n "$ip" ]; then
                detected_ips+=("$ip")
            fi
        done
        
        if [ ${#detected_ips[@]} -gt 0 ]; then
            local unique_ips=($(printf "%s\n" "${detected_ips[@]}" | sort -u))
            write_log "✓ 检测到 ${#unique_ips[@]} 个IP: ${unique_ips[*]}"
            printf "%s\n" "${unique_ips[@]}"
            return 0
        fi
        
        retry_count=$((retry_count + 1))
    done
    
    write_log "✗ 无法获取IP"
    return 1
}

# 修复：只记录IP到历史文件，日志写入LOG_FILE
add_to_history() {
    local ips=("$@")
    local device_id=$(get_device_id)
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    for ip in "${ips[@]}"; do
        # 只写入纯净的IP记录到历史文件
        echo "$timestamp | Device: $device_id | IP: $ip" >> "$IP_HISTORY_FILE"
        # 日志信息写入日志文件
        write_log "记录IP: $ip"
    done
    
    local history_count=$(wc -l < "$IP_HISTORY_FILE" 2>/dev/null || echo 0)
    if [ "$history_count" -gt "$MAX_HISTORY_SIZE" ]; then
        tail -n "$MAX_HISTORY_SIZE" "$IP_HISTORY_FILE" > "$IP_HISTORY_FILE.tmp"
        mv "$IP_HISTORY_FILE.tmp" "$IP_HISTORY_FILE"
    fi
}

export_simple_list() {
    if [ -f "$IP_HISTORY_FILE" ]; then
        awk -F'IP: ' '{print $2}' "$IP_HISTORY_FILE" | grep -v '^$' | sort -u > "$IP_EXPORT_SIMPLE"
        local count=$(wc -l < "$IP_EXPORT_SIMPLE")
        write_log "✓ 导出IP列表: $count 个"
    fi
}

# 修复：改进JSON数据导出逻辑
export_json_data() {
    local device_id=$(get_device_id)
    
    declare -A ip_last_seen
    
    if [ -f "$IP_HISTORY_FILE" ]; then
        # 只处理IP_HISTORY_FILE，不处理LOG_FILE
        while IFS='|' read -r timestamp device ip_part; do
            # 提取IP地址（去除"IP: "前缀和空格）
            local ip=$(echo "$ip_part" | sed 's/^[[:space:]]*IP:[[:space:]]*//' | xargs)
            local time=$(echo "$timestamp" | xargs)
            
            # 验证IP格式，只保留有效的IP地址
            if [ -n "$ip" ] && validate_ip "$ip"; then
                ip_last_seen["$ip"]="$time"
            fi
        done < "$IP_HISTORY_FILE"
    fi
    
    # 生成JSON
    echo "{" > "$IP_EXPORT_JSON"
    echo "  \"device_id\": \"$device_id\"," >> "$IP_EXPORT_JSON"
    echo "  \"hostname\": \"$(hostname 2>/dev/null || echo 'unknown')\"," >> "$IP_EXPORT_JSON"
    echo "  \"collected_at\": \"$(date '+%Y-%m-%d %H:%M:%S')\"," >> "$IP_EXPORT_JSON"
    echo "  \"ip_count\": ${#ip_last_seen[@]}," >> "$IP_EXPORT_JSON"
    echo "  \"ips\": [" >> "$IP_EXPORT_JSON"
    
    local is_first=true
    for ip in "${!ip_last_seen[@]}"; do
        if [ "$is_first" = true ]; then
            is_first=false
        else
            echo "," >> "$IP_EXPORT_JSON"
        fi
        
        echo -n "    {\"ip\": \"$ip\", \"last_seen\": \"${ip_last_seen[$ip]}\"}" >> "$IP_EXPORT_JSON"
    done
    
    echo "" >> "$IP_EXPORT_JSON"
    echo "  ]" >> "$IP_EXPORT_JSON"
    echo "}" >> "$IP_EXPORT_JSON"
    
    write_log "✓ 导出JSON数据"
}

upload_via_ftp() {
    if [ -z "$FTP_HOST" ] || [ -z "$FTP_USER" ] || [ -z "$FTP_PASS" ]; then
        write_log "✗ FTP配置不完整"
        return 1
    fi
    
    if [ ! -f "$IP_EXPORT_JSON" ]; then
        write_log "✗ JSON文件不存在"
        return 1
    fi
    
    local device_id=$(get_device_id)
    local remote_filename="${device_id}.json"
    
    write_log "📤 通过FTP上传数据..."
    write_log "FTP服务器: $FTP_HOST:$FTP_PORT"
    write_log "远程文件名: $remote_filename"
    
    local ftp_url="ftp://$FTP_HOST:$FTP_PORT$FTP_UPLOAD_DIR/$remote_filename"
    
    local response=$(curl -s -T "$IP_EXPORT_JSON" \
        --user "$FTP_USER:$FTP_PASS" \
        "$ftp_url" \
        --ftp-create-dirs \
        --max-time 60 \
        -w "HTTP_CODE:%{http_code}\nFTP_CODE:%{response_code}" 2>&1)
    
    local curl_code=$?
    
    write_log "curl退出码: $curl_code"
    
    if [ $curl_code -eq 0 ]; then
        write_log "✓✓✓ FTP上传成功"
        write_log "远程路径: $FTP_UPLOAD_DIR/$remote_filename"
        
        if [ -f "$IP_EXPORT_SIMPLE" ]; then
            local txt_url="ftp://$FTP_HOST:$FTP_PORT$FTP_UPLOAD_DIR/${device_id}.txt"
            curl -s -T "$IP_EXPORT_SIMPLE" \
                --user "$FTP_USER:$FTP_PASS" \
                "$txt_url" \
                --ftp-create-dirs \
                --max-time 30 2>&1
            write_log "✓ 同时上传了TXT文件"
        fi
        
        # ⭐ FTP上传成功后，自动调用处理接口
        write_log "触发服务器处理上传文件..."
        local process_url="https://myip.zsanjin.de/api/process"
        
        local process_temp="/tmp/process_response_$$.txt"
        local process_http_code=$(curl -s -w "%{http_code}" \
            -X GET "$process_url" \
            -H "X-API-Key: $API_KEY" \
            -o "$process_temp" \
            --max-time 10 2>&1)
        
        local process_code=$?
        local process_response=""
        if [ -f "$process_temp" ]; then
            process_response=$(cat "$process_temp")
            rm -f "$process_temp"
        fi
        
        write_log "处理接口HTTP状态码: $process_http_code"
        write_log "处理接口响应: $process_response"
        
        if [ $process_code -eq 0 ] && [ "$process_http_code" = "200" ]; then
            write_log "✓ 服务器处理完成"
        else
            write_log "⚠️  自动处理调用失败 (curl退出码: $process_code, HTTP: $process_http_code)"
        fi
        
        return 0
    else
        write_log "✗✗✗ FTP上传失败"
        write_log "响应: $response"
        
        case "$curl_code" in
            6)  write_log "原因: 无法解析FTP主机名" ;;
            7)  write_log "原因: 无法连接到FTP服务器" ;;
            9)  write_log "原因: FTP访问被拒绝" ;;
            28) write_log "原因: FTP连接超时" ;;
            67) write_log "原因: FTP登录失败（用户名或密码错误）" ;;
            78) write_log "原因: 远程文件未找到或无权限" ;;
            *)  write_log "curl错误码: $curl_code" ;;
        esac
        
        return 1
    fi
}

upload_via_http() {
    if [ -z "$UPLOAD_URL" ]; then
        write_log "⚠️  未配置HTTP上传URL"
        return 1
    fi
    
    if [ ! -f "$IP_EXPORT_JSON" ]; then
        write_log "✗ JSON文件不存在"
        return 1
    fi
    
    write_log "📤 通过HTTP API上传数据..."
    write_log "目标URL: $UPLOAD_URL"
    
    local temp_response="/tmp/upload_response.txt"
    local temp_headers="/tmp/upload_headers.txt"
    
    local http_code=$(curl -s -w "%{http_code}" \
        -X POST "$UPLOAD_URL" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        -d @"$IP_EXPORT_JSON" \
        -o "$temp_response" \
        -D "$temp_headers" \
        --max-time 30 2>&1)
    
    local curl_exit_code=$?
    
    write_log "curl退出码: $curl_exit_code"
    write_log "HTTP状态码: $http_code"
    
    local response=""
    if [ -f "$temp_response" ]; then
        response=$(cat "$temp_response")
    fi
    
    case "$http_code" in
        200|201)
            write_log "✓✓✓ HTTP上传成功 (HTTP $http_code)"
            write_log "服务器响应: $response"
            rm -f "$temp_response" "$temp_headers"
            return 0
            ;;
        *)
            write_log "✗✗✗ HTTP上传失败 (HTTP $http_code)"
            write_log "错误详情: ${response:0:200}"
            rm -f "$temp_response" "$temp_headers"
            return 1
            ;;
    esac
}

upload_to_server() {
    case "$UPLOAD_METHOD" in
        ftp|FTP)
            upload_via_ftp
            local result=$?
            if [ $result -ne 0 ]; then
                write_log "⚠️  FTP上传失败，尝试HTTP方式..."
                upload_via_http
                return $?
            fi
            return $result
            ;;
        http|HTTP)
            upload_via_http
            ;;
        *)
            write_log "✗ 未知的上传方式: $UPLOAD_METHOD"
            return 1
            ;;
    esac
}

main() {
    write_log ""
    write_log "========================================"
    write_log "IP收集任务开始"
    write_log "========================================"
    
    init_workdir
    
    local device_id=$(get_device_id)
    write_log "设备ID: $device_id"
    
    mapfile -t current_ips < <(get_current_ips)
    
    if [ ${#current_ips[@]} -eq 0 ]; then
        write_log "✗ 无法获取IP，任务终止"
        write_log "========================================"
        exit 1
    fi
    
    add_to_history "${current_ips[@]}"
    export_simple_list
    export_json_data
    upload_to_server
    
    write_log "任务完成"
    write_log "========================================"
    
    echo ""
    echo "生成的文件："
    echo "  简易列表: $IP_EXPORT_SIMPLE"
    echo "  JSON数据: $IP_EXPORT_JSON"
    echo "  设备ID:   $device_id"
    echo ""
}

main
