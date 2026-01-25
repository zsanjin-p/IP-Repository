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

init_workdir() {
    if [ ! -d "$WORK_DIR" ]; then
        mkdir -p "$WORK_DIR"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 创建工作目录: $WORK_DIR" >> "$LOG_FILE"
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
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 生成设备ID: $device_id" >> "$LOG_FILE"
    
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
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] → 尝试: $service" >> "$LOG_FILE"
    
    local response=$(curl -s --max-time "$timeout" --connect-timeout 3 "$service" 2>&1)
    local curl_exit_code=$?
    
    if [ $curl_exit_code -ne 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')]   ✗ 连接失败" >> "$LOG_FILE"
        return 1
    fi
    
    if [ -z "$response" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')]   ✗ 响应为空" >> "$LOG_FILE"
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
        echo "[$(date '+%Y-%m-%d %H:%M:%S')]   ✗ 无法解析IP" >> "$LOG_FILE"
        return 1
    fi
    
    if validate_ip "$ip"; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')]   ✓ 检测到IP: $ip" >> "$LOG_FILE"
        echo "$ip"
        return 0
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')]   ✗ IP验证失败: $ip" >> "$LOG_FILE"
        return 1
    fi
}

get_current_ips() {
    local retry_count=0
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        if [ $retry_count -gt 0 ]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⟳ 第 $((retry_count + 1)) 次尝试..." >> "$LOG_FILE"
            sleep $RETRY_DELAY
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始检测公网IP..." >> "$LOG_FILE"
        fi
        
        local detected_ips=()
        
        for service in "${IP_SERVICES[@]}"; do
            ip=$(get_ip_from_service "$service" 5)
            if [ $? -eq 0 ] && [ -n "$ip" ]; then
                detected_ips+=("$ip")
            fi
            
            if [ ${#detected_ips[@]} -ge 3 ]; then
                break
            fi
        done
        
        if [ ${#detected_ips[@]} -gt 0 ]; then
            local unique_ips=($(printf "%s\n" "${detected_ips[@]}" | sort -u))
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ 检测到 ${#unique_ips[@]} 个IP: ${unique_ips[*]}" >> "$LOG_FILE"
            printf "%s\n" "${unique_ips[@]}"
            return 0
        fi
        
        retry_count=$((retry_count + 1))
    done
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗ 无法获取IP" >> "$LOG_FILE"
    return 1
}

add_to_history() {
    local ips=("$@")
    local device_id=$(get_device_id)
    
    for ip in "${ips[@]}"; do
        echo "$(date '+%Y-%m-%d %H:%M:%S') | Device: $device_id | IP: $ip" >> "$IP_HISTORY_FILE"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 记录IP: $ip" >> "$LOG_FILE"
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
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ 导出IP列表: $count 个" >> "$LOG_FILE"
    fi
}

export_json_data() {
    local device_id=$(get_device_id)
    
    declare -A ip_last_seen
    
    if [ -f "$IP_HISTORY_FILE" ]; then
        while IFS='|' read -r timestamp device ip_part; do
            local ip=$(echo "$ip_part" | awk '{print $2}')
            local time=$(echo "$timestamp" | xargs)
            
            if [ -n "$ip" ]; then
                ip_last_seen["$ip"]="$time"
            fi
        done < "$IP_HISTORY_FILE"
    fi
    
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
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ 导出JSON数据" >> "$LOG_FILE"
}

upload_via_ftp() {
    if [ -z "$FTP_HOST" ] || [ -z "$FTP_USER" ] || [ -z "$FTP_PASS" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗ FTP配置不完整" >> "$LOG_FILE"
        return 1
    fi
    
    if [ ! -f "$IP_EXPORT_JSON" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗ JSON文件不存在" >> "$LOG_FILE"
        return 1
    fi
    
    local device_id=$(get_device_id)
    local remote_filename="${device_id}.json"
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 📤 通过FTP上传数据..." >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] FTP服务器: $FTP_HOST:$FTP_PORT" >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 远程文件名: $remote_filename" >> "$LOG_FILE"
    
    local ftp_url="ftp://$FTP_HOST:$FTP_PORT$FTP_UPLOAD_DIR/$remote_filename"
    
    local response=$(curl -s -T "$IP_EXPORT_JSON" \
        --user "$FTP_USER:$FTP_PASS" \
        "$ftp_url" \
        --ftp-create-dirs \
        --max-time 60 \
        -w "HTTP_CODE:%{http_code}\nFTP_CODE:%{response_code}" 2>&1)
    
    local curl_code=$?
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] curl退出码: $curl_code" >> "$LOG_FILE"
    
    if [ $curl_code -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓✓✓ FTP上传成功" >> "$LOG_FILE"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 远程路径: $FTP_UPLOAD_DIR/$remote_filename" >> "$LOG_FILE"
        
        if [ -f "$IP_EXPORT_SIMPLE" ]; then
            local txt_url="ftp://$FTP_HOST:$FTP_PORT$FTP_UPLOAD_DIR/${device_id}.txt"
            curl -s -T "$IP_EXPORT_SIMPLE" \
                --user "$FTP_USER:$FTP_PASS" \
                "$txt_url" \
                --ftp-create-dirs \
                --max-time 30 2>&1
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ 同时上传了TXT文件" >> "$LOG_FILE"
        fi
        
        return 0
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗✗✗ FTP上传失败" >> "$LOG_FILE"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 响应: $response" >> "$LOG_FILE"
        
        case "$curl_code" in
            6)  echo "[$(date '+%Y-%m-%d %H:%M:%S')] 原因: 无法解析FTP主机名" >> "$LOG_FILE" ;;
            7)  echo "[$(date '+%Y-%m-%d %H:%M:%S')] 原因: 无法连接到FTP服务器" >> "$LOG_FILE" ;;
            9)  echo "[$(date '+%Y-%m-%d %H:%M:%S')] 原因: FTP访问被拒绝" >> "$LOG_FILE" ;;
            28) echo "[$(date '+%Y-%m-%d %H:%M:%S')] 原因: FTP连接超时" >> "$LOG_FILE" ;;
            67) echo "[$(date '+%Y-%m-%d %H:%M:%S')] 原因: FTP登录失败（用户名或密码错误）" >> "$LOG_FILE" ;;
            78) echo "[$(date '+%Y-%m-%d %H:%M:%S')] 原因: 远程文件未找到或无权限" >> "$LOG_FILE" ;;
            *)  echo "[$(date '+%Y-%m-%d %H:%M:%S')] curl错误码: $curl_code" >> "$LOG_FILE" ;;
        esac
        
        return 1
    fi
}

upload_via_http() {
    if [ -z "$UPLOAD_URL" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️  未配置HTTP上传URL" >> "$LOG_FILE"
        return 1
    fi
    
    if [ ! -f "$IP_EXPORT_JSON" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗ JSON文件不存在" >> "$LOG_FILE"
        return 1
    fi
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 📤 通过HTTP API上传数据..." >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 目标URL: $UPLOAD_URL" >> "$LOG_FILE"
    
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
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] curl退出码: $curl_exit_code" >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] HTTP状态码: $http_code" >> "$LOG_FILE"
    
    local response=""
    if [ -f "$temp_response" ]; then
        response=$(cat "$temp_response")
    fi
    
    case "$http_code" in
        200|201)
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓✓✓ HTTP上传成功 (HTTP $http_code)" >> "$LOG_FILE"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] 服务器响应: $response" >> "$LOG_FILE"
            rm -f "$temp_response" "$temp_headers"
            return 0
            ;;
        *)
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗✗✗ HTTP上传失败 (HTTP $http_code)" >> "$LOG_FILE"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] 错误详情: ${response:0:200}" >> "$LOG_FILE"
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
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️  FTP上传失败，尝试HTTP方式..." >> "$LOG_FILE"
                upload_via_http
                return $?
            fi
            return $result
            ;;
        http|HTTP)
            upload_via_http
            ;;
        *)
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗ 未知的上传方式: $UPLOAD_METHOD" >> "$LOG_FILE"
            return 1
            ;;
    esac
}

main() {
    echo "" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] IP收集任务开始" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    
    init_workdir
    
    local device_id=$(get_device_id)
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 设备ID: $device_id" >> "$LOG_FILE"
    
    mapfile -t current_ips < <(get_current_ips)
    
    if [ ${#current_ips[@]} -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗ 无法获取IP，任务终止" >> "$LOG_FILE"
        echo "========================================" >> "$LOG_FILE"
        exit 1
    fi
    
    add_to_history "${current_ips[@]}"
    export_simple_list
    export_json_data
    upload_to_server
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 任务完成" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    
    echo ""
    echo "生成的文件："
    echo "  简易列表: $IP_EXPORT_SIMPLE"
    echo "  JSON数据: $IP_EXPORT_JSON"
    echo "  设备ID:   $device_id"
    echo ""
}

main
