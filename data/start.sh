#!/usr/bin/env bash

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

get_vpn_if_gw() {
    local vpn_if_hex_addr=''
    local vpn_if_dec_addr=''
    local vpn_if_addr=''
    local try_ip=''
    local vpn_if_gw=''

    vpn_if_hex_addr=$(grep "${VPN_IF_NAME}" /proc/net/route | awk '$2 == "00000000" { print $3 }')
    
    if [ -n "${vpn_if_hex_addr}" ]; then
        #shellcheck disable=SC2046
        vpn_if_dec_addr=$(printf "%d." $(echo "${vpn_if_hex_addr}" | sed 's/../0x& /g' | tr ' ' '\n' | tac) | sed 's/\.$/\n/')
    fi

    if [ -z "${vpn_if_dec_addr}" ]; then
        vpn_if_addr=$(ip addr show dev "${VPN_IF_NAME}" | grep -oP '([0-9]{1,3}[\.]){3}[0-9]{1,3}')
        for n in {1..254}; do
            try_ip="$(echo "${vpn_if_addr}" | cut -d'.' -f1-3).${n}"
            if [ "${try_ip}" != "${vpn_if_addr}" ]; then
                if nc -4 -vw1 "${try_ip}" 1 &>/dev/null 2>&1; then
                    vpn_if_gw=${try_ip}
                    break
                fi
            fi
        done
        if [ -n "${vpn_if_gw}" ]; then
            echo "${vpn_if_gw}"
        else
            return 1
        fi
    else 
        echo "${vpn_if_dec_addr}"
    fi
}

getpublicip() {
    # shellcheck disable=SC2086
    natpmpc -g ${VPN_GATEWAY} | grep -oP '(?<=Public.IP.address.:.).*'
}

findconfiguredport() {
    curl -s --location "$TRANSMISSION_SERVER:$TRANSMISSION_PORT/transmission/rpc" --header "X-Transmission-Session-Id: $transmission_sid" --header "Content-Type: application/json" --data '{"arguments": { "fields": ["peer-port"] }, "method": "session-get"}' | grep -oP '(?<="peer-port":)(\d{1,5})'
}

findactiveport() {
    # shellcheck disable=SC2086
    natpmpc -g ${VPN_GATEWAY} -a 0 0 udp ${NAT_LEASE_LIFETIME} >/dev/null 2>&1
    # shellcheck disable=SC2086
    natpmpc -g ${VPN_GATEWAY} -a 0 0 tcp ${NAT_LEASE_LIFETIME} | grep -oP '(?<=Mapped public port.).*(?=.protocol.*)'
}

transmission_login() {
    transmission_sid=$(curl -s --location "http://${TRANSMISSION_SERVER}:${TRANSMISSION_PORT}/transmission/rpc" | grep -oP '<code>X-Transmission-Session-Id: \K.*?(?=<\/code>)')
    return $?
}

transmission_changeport() {
    curl -s --location "http://$TRANSMISSION_SERVER:$TRANSMISSION_PORT/transmission/rpc" --header "X-Transmission-Session-Id: $1" --header "Content-Type: application/json" --data "{\"arguments\": {\"peer-port\": $port, \"peer-port-random-on-start\": false, \"port-forwarding-enabled\": false}, \"method\": \"session-set\"}" >/dev/null 2>&1
    return $?
}

transmission_checksid() {
    if curl -s --location --request POST "http://${TRANSMISSION_SERVER}:${TRANSMISSION_PORT}/transmission/rpc" --header 'X-Transmission-Session-Id: ${transmission_sid}' | grep -qi 409 ; then
        return 1
    else
        return 0
    fi
}

transmission_isreachable() {
    nc -4 -zw5 ${TRANSMISSION_SERVER} ${TRANSMISSION_PORT} >/dev/null 2>&1
}

fw_delrule(){
    if (docker exec "${VPN_CT_NAME}" /sbin/iptables -L INPUT -n | grep -qP "^ACCEPT.*${configured_port}.*"); then
        # shellcheck disable=SC2086
        docker exec "${VPN_CT_NAME}" /sbin/iptables -D INPUT -i "${VPN_IF_NAME}" -p tcp --dport ${configured_port} -j ACCEPT
        # shellcheck disable=SC2086
        docker exec "${VPN_CT_NAME}" /sbin/iptables -D INPUT -i "${VPN_IF_NAME}" -p udp --dport ${configured_port} -j ACCEPT
    fi
}

fw_addrule(){
    if ! (docker exec "${VPN_CT_NAME}" /sbin/iptables -L INPUT -n | grep -qP "^ACCEPT.*${active_port}.*"); then
        # shellcheck disable=SC2086
        docker exec "${VPN_CT_NAME}" /sbin/iptables -A INPUT -i "${VPN_IF_NAME}" -p tcp --dport ${active_port} -j ACCEPT
        # shellcheck disable=SC2086
        docker exec "${VPN_CT_NAME}" /sbin/iptables -A INPUT -i "${VPN_IF_NAME}" -p udp --dport ${active_port} -j ACCEPT
        return 0
    else
        return 1
    fi
}

get_portmap() {
    res=0
    public_ip=$(getpublicip)

    if ! transmission_checksid; then
        echo "$(timestamp) | Transmission Cookie invalid, getting new SessionID"
        if ! transmission_login; then
            echo "$(timestamp) | Failed getting new SessionID from Transmission"
	          return 1
        fi
    else
        echo "$(timestamp) | Transmission SessionID Ok!"
    fi

    configured_port=$(findconfiguredport "${transmission_sid}")
    active_port=$(findactiveport)

    echo "$(timestamp) | Public IP: ${public_ip}"
    echo "$(timestamp) | Configured Port: ${configured_port}"
    echo "$(timestamp) | Active Port: ${active_port}"

    # shellcheck disable=SC2086
    if [ ${configured_port} != ${active_port} ]; then
        if transmission_changeport "${transmission_sid}" ${active_port}; then
            if fw_delrule; then
                echo "$(timestamp) | IPTables rule deleted for port ${configured_port} on ${VPN_CT_NAME} container"
            fi
            echo "$(timestamp) | Port Changed to: $(findconfiguredport ${transmission_sid})"
        else
            echo "$(timestamp) | Port Change failed."
            res=1
        fi
    else
        echo "$(timestamp) | Port OK (Act: ${active_port} Cfg: ${configured_port})"
    fi

    if fw_addrule; then
        echo "$(timestamp) | IPTables rule added for port ${active_port} on ${VPN_CT_NAME} container"
    fi

    return $res
}

check_vpn_ct_health() {
    while true;
    do
        if ! docker inspect "${VPN_CT_NAME}" --format='{{json .State.Health.Status}}' | grep -q '"healthy"'; then
            echo "$(timestamp) | Waiting for ${VPN_CT_NAME} healthy state.."
            sleep 3
        else
            echo "$(timestamp) | VPN container ${VPN_CT_NAME} in healthy state!"
            break
        fi
    done
}

pre_reqs() {
    if [ -z "${VPN_GATEWAY}" ]; then
        VPN_GATEWAY=$(get_vpn_if_gw || echo '')
    fi
while read -r var; do
    [ -z "${!var}" ] && { echo "$(timestamp) | ${var} is empty or not set."; exit 1; }
done << EOF
TRANSMISSION_SERVER
TRANSMISSION_PORT
TRANSMISSION_USER
TRANSMISSION_PASS
VPN_GATEWAY
VPN_CT_NAME
VPN_IF_NAME
CHECK_INTERVAL
NAT_LEASE_LIFETIME
EOF

[ ! -S /var/run/docker.sock ] && { echo "$(timestamp) | Docker socket doesn't exist or is inaccessible"; exit 2; }

return 0
}

load_vals(){
    public_ip=$(getpublicip)
    if transmission_isreachable; then
        if transmission_login; then
            configured_port=$(findconfiguredport "${transmission_sid}")
        else
            echo "$(timestamp) | Unable to login to Transmission at ${TRANSMISSION_SERVER}:${TRANSMISSION_PORT}"
            exit 7
        fi
    else
        echo "$(timestamp) | Unable to reach Transmission at ${TRANSMISSION_SERVER}:${TRANSMISSION_PORT}"
        exit 6
    fi
    active_port=''
}

public_ip=
configured_port=
active_port=
transmission_sid=

# Wait for a healthy state on the VPN container
check_vpn_ct_health

if pre_reqs; then load_vals; fi

# shellcheck disable=SC2086
[ -z ${public_ip} ] && { echo "$(timestamp) | Unable to grab VPN Public IP. Please check configuration"; exit 3; }
# shellcheck disable=SC2086
[ -z ${configured_port} ] && { echo "$(timestamp) | Transmission configured port value is empty(?). Please check configuration"; exit 4; }
[ -z "${transmission_sid}" ] && { echo "$(timestamp) | Unable to grab Transmission SessionID. Please check configuration"; exit 5; }

while true;
do
    if get_portmap; then
        echo "$(timestamp) | NAT-PMP/UPnP Ok!"
    else
        echo "$(timestamp) | NAT-PMP/UPnP Failed"
    fi
    # shellcheck disable=SC2086
    echo "$(timestamp) | Sleeping for $(echo ${CHECK_INTERVAL}/60 | bc) minutes"
    # shellcheck disable=SC2086
    sleep ${CHECK_INTERVAL}
done

exit $?
