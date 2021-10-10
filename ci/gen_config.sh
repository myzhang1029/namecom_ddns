#!/bin/sh

case "$(uname)" in
    Darwin)
        iface=en0
        ;;
    Linux)
        iface="$(ip addr|grep UP|cut -d: -f2|grep -v lo|head -n 1|xargs)"
        ;;
    MINGW*)
        iface="$(netsh interface ip show addresses|grep Configuration|awk '{print $4}'|head -n 1|xargs)"
        ;;
    *)
        iface="lo"
        ;;
esac

cat > ci_config.toml << EOF
# DDNS configuration for ${TEST_NAMECOM_HOST}.${TEST_NAMECOM_ZONE}

[core]
url = "https://${TEST_NAMECOM_URL}"
username = "${TEST_NAMECOM_USER}"
key = "${TEST_NAMECOM_KEY}"

[[records]]
host = "${TEST_NAMECOM_HOST}"
zone = "${TEST_NAMECOM_ZONE}"
type = "A"
ttl = 300
method = "local"
interface = "${iface}"
EOF
