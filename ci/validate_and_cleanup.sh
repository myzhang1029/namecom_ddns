#!/bin/sh
ping -c3 "${TEST_NAMECOM_HOST}.${TEST_NAMECOM_ZONE}" > /dev/null 2>&1
result=$?
curl -u "${TEST_NAMECOM_USER}:${TEST_NAMECOM_KEY}" "${TEST_NAMECOM_URL}/v4/domains/${TEST_NAMECOM_ZONE}/records" | jq ".records[] | if .host == \"${TEST_NAMECOM_HOST}\" then .id else empty end" | xargs -I {} curl -X DELETE -u "${TEST_NAMECOM_USER}:${TEST_NAMECOM_KEY}" "${TEST_NAMECOM_URL}/v4/domains/${TEST_NAMECOM_ZONE}/records/{}" 
exit $?
