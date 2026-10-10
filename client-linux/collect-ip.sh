#!/bin/bash

# =====================================
# IP收集上传脚本 (Bash版)
# =====================================

# 配置信息
UPLOAD_URL="https://ip.ex.com/api/upload-ip"
API_KEY="your_secret_api_key_here"

UPLOAD_METHOD="http"

FTP_HOST="ftp.ex.com"
FTP_PORT=21
FTP_USER="user"
FTP_PASS="passwd"
FTP_UPLOAD_DIR="/api/uploads"

# 文件路径配置
WORK_DIR="/root/project/myiplist"
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

# ---- IPv6 ----
# 只返回 IPv6 的服务（域名只有 AAAA 记录），配合 curl -6 使用
ENABLE_IPV6=true
IP6_SERVICES=(
    "https://6.ipw.cn"
    "https://api6.ipify.org"
    "https://ipv6.icanhazip.com"
    "https://v6.ident.me"
    "https://api-ipv6.ip.sb/ip"
    "https://ipv6.seeip.org"
    "https://ip6.nnev.de"
    "https://ipv6.wtfismyip.com/text"
    "https://ipv6.ipleak.net/json"
    "https://ifconfig.co/ip"
    "https://ifconfig.me/ip"
    "https://icanhazip.com"
    "https://ident.me"
    "https://checkip.amazonaws.com"
)
IP6_MAX_CONSECUTIVE_FAIL=3   # 连续失败这么多次就认为没有 IPv6 出口，不再往下试

# 网卡兜底：直接读本机网卡上的全球 IPv6（开了 v2ray / 代理时，外部服务查到的是代理出口，查不到本机真实 v6）
IPV6_USE_NIC=true
IPV6_NIC_MAX=6
# 本机网卡没有全球 IPv6 时，是否仍用外部服务探测（只有“本机无 v6、但代理出口有 v6”才需要；关闭可省掉超时等待）
IPV6_PROBE_WITHOUT_LOCAL=false

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
    
    local response=$(curl -4 -s --max-time "$timeout" --connect-timeout 3 "$service" 2>&1)
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

# JSON 字符串转义（去掉控制字符，转义反斜杠和引号）
json_escape() {
    printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# 收集系统信息，输出一段 JSON 对象（用于服务端显示系统图标）
detect_os_json() {
    local family="linux" id="" name="" version="" kernel arch uname_s
    uname_s=$(uname -s 2>/dev/null)
    kernel=$(uname -r 2>/dev/null)
    arch=$(uname -m 2>/dev/null)

    if [ "$uname_s" = "Darwin" ]; then
        family="macos"; id="macos"
        name="$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
        version=$(sw_vers -productVersion 2>/dev/null)
    elif [ -r /etc/os-release ]; then
        id=$(. /etc/os-release 2>/dev/null; echo "${ID:-}")
        name=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-$NAME}")
        version=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")
    elif [ -r /etc/redhat-release ]; then
        name=$(head -1 /etc/redhat-release)
    fi
    [ -z "$name" ] && name="$uname_s $kernel"

    printf '{"family": "%s", "id": "%s", "name": "%s", "version": "%s", "kernel": "%s", "arch": "%s"}' \
        "$family" "$(json_escape "$id")" "$(json_escape "$name")" "$(json_escape "$version")" \
        "$(json_escape "$kernel")" "$(json_escape "$arch")"
}

# IPv6 校验：只接受全球单播 2000::/3（和服务端规则一致）
validate_ip6() {
    local ip="$1"
    [ "${#ip}" -le 45 ] || return 1
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] || return 1
    [[ "$ip" == *:*:* ]] || return 1
    [[ "$ip" =~ ^[23][0-9a-fA-F]{0,3}: ]] || return 1
    return 0
}

validate_any_ip() {
    validate_ip "$1" || validate_ip6 "$1"
}

# 隧道地址不算：Teredo(2001:0::/32)、6to4(2002::/16)
is_usable_ip6() {
    local ip="${1,,}"
    validate_ip6 "$ip" || return 1
    [[ "$ip" =~ ^(2002:|2001:0:|2001:0000:) ]] && return 1
    return 0
}

# 读取本机网卡上的全球 IPv6（排除 fe80 / ULA / 回环 / 隧道 / 已弃用的临时地址 / 容器虚拟网卡）
get_local_ip6_addrs() {
    command -v ip >/dev/null 2>&1 || return 1
    local line dev addr
    ip -6 -o addr show scope global 2>/dev/null | while read -r line; do
        [[ "$line" =~ (deprecated|tentative|dadfailed) ]] && continue
        dev=$(echo "$line" | awk '{print $2}')
        [[ "$dev" =~ ^(lo|docker|br-|veth|virbr|tun|tap) ]] && continue
        addr=$(echo "$line" | awk '{print $4}'); addr="${addr%%/*}"
        is_usable_ip6 "$addr" && echo "${addr,,}"
    done | sort -u | head -n "$IPV6_NIC_MAX"
}

# 只接受“整个返回内容就是一个 IPv6”，或 JSON 里的 ip 字段；
# 不在整段文本里找第一个像 IPv6 的串（否则 JSON 里的网段、DNS 等无关地址会被当成自己的 IP）
get_ip6_from_service() {
    local service="$1"
    write_log "→ 尝试(v6): $service"
    local response
    response=$(curl -6 -s --max-time 6 --connect-timeout 3 "$service" 2>&1)
    if [ $? -ne 0 ] || [ -z "$response" ]; then
        write_log "  ✗ 连接失败或响应为空"
        return 1
    fi

    local candidate
    candidate=$(printf '%s' "$response" | tr -d '[:space:]')
    if [[ "$candidate" == \{* ]]; then
        candidate=$(printf '%s' "$response" | grep -oE '"(ip|IP|query|ip_addr)"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*:[[:space:]]*"([^"]+)"/\1/')
    fi

    if [ -n "$candidate" ] && is_usable_ip6 "$candidate"; then
        candidate="${candidate,,}"
        write_log "  ✓ 检测到IPv6: $candidate"
        echo "$candidate"
        return 0
    fi
    write_log "  ✗ 返回内容不是单个全球单播 IPv6，已忽略: ${response:0:60}"
    return 1
}

# 获取当前公网 IPv6：网卡地址 + 外部服务结果，取并集
# 不走代理时网卡地址就是对外源地址（v6 一般没有 NAT）；走代理时外部服务看到的是代理出口，两者互补
get_current_ips6() {
    if [ "$ENABLE_IPV6" != "true" ]; then return 1; fi

    local all=() local_addrs=() a
    mapfile -t local_addrs < <(get_local_ip6_addrs)
    if [ ${#local_addrs[@]} -gt 0 ]; then
        write_log "✓ 网卡上的全球IPv6 (${#local_addrs[@]} 个): ${local_addrs[*]}"
        [ "$IPV6_USE_NIC" = "true" ] && all+=("${local_addrs[@]}")
    else
        write_log "网卡上没有可用的全球 IPv6 地址"
        if [ "$IPV6_PROBE_WITHOUT_LOCAL" != "true" ]; then
            write_log "跳过外部 IPv6 检测（本机无全球 IPv6）"
            return 1
        fi
    fi

    write_log "开始检测公网IPv6..."
    local fail=0 found=0 service ip
    for service in "${IP6_SERVICES[@]}"; do
        ip=$(get_ip6_from_service "$service")
        if [ $? -eq 0 ] && [ -n "$ip" ]; then
            all+=("$ip"); found=$((found + 1)); fail=0
        else
            fail=$((fail + 1))
            if [ "$found" -eq 0 ] && [ "$fail" -ge "$IP6_MAX_CONSECUTIVE_FAIL" ]; then
                write_log "连续 $fail 个服务失败，认为外部服务查不到 IPv6（开了代理时很常见，已有网卡地址兜底）"
                break
            fi
        fi
    done

    if [ ${#all[@]} -gt 0 ]; then
        local unique=($(printf "%s\n" "${all[@]}" | sort -u))
        write_log "✓ 共 ${#unique[@]} 个IPv6: ${unique[*]}"
        printf "%s\n" "${unique[@]}"
        return 0
    fi
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
            if [ -n "$ip" ] && validate_any_ip "$ip"; then
                ip_last_seen["$ip"]="$time"
            fi
        done < "$IP_HISTORY_FILE"
    fi
    
    # 生成JSON
    echo "{" > "$IP_EXPORT_JSON"
    echo "  \"device_id\": \"$device_id\"," >> "$IP_EXPORT_JSON"
    echo "  \"hostname\": \"$(json_escape "$(hostname 2>/dev/null || echo 'unknown')")\"," >> "$IP_EXPORT_JSON"
    echo "  \"os\": $(detect_os_json)," >> "$IP_EXPORT_JSON"
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

    # IPv6（可选，没有就跳过）
    local current_ips6=()
    mapfile -t current_ips6 < <(get_current_ips6)
    current_ips+=("${current_ips6[@]}")
    # 去掉空行
    local cleaned=()
    for x in "${current_ips[@]}"; do [ -n "$x" ] && cleaned+=("$x"); done
    current_ips=("${cleaned[@]}")

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