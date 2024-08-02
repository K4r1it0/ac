#!/bin/bash

# Variables
PORT=13443
AUTH_USERNAME="admin@admin.com"
AUTH_PASSWORD="3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2"
TARGET=$1
PROFILE_ID="11111111-1111-1111-1111-111111111112"
#1111111-1111-1111-1111-111111111112  Full 
#11111111-1111-1111-1111-111111111112 Critical-High
#11111111-1111-1111-1111-111111111119 Critical-High-Medium
#11111111-1111-1111-1111-111111111116 XSS
REPORT_TEMPLATE_ID="11111111-1111-1111-1111-111111111111"
INCREMENTAL=false
BASE_URL="https://127.0.0.1:${PORT}"
AUTH_TOKEN=""
CRITICAL_VULN_FOUND=0

# Function to get Auth Token
get_auth_token() {
    AUTH_TOKEN=$(curl -sk -D - -X POST "${BASE_URL}/api/v1/me/login" \
        -H "Content-Type: application/json" \
        -d '{"email": "'"${AUTH_USERNAME}"'", "password": "'"${AUTH_PASSWORD}"'", "remember_me": true}' \
        | grep 'X-Auth:' | awk '{print $2}' | tr -d '\r')
    if [ -z "${AUTH_TOKEN}" ]; then
        echo "Unable to retrieve auth token. Check credentials."
        exit 1
    fi
    echo "Auth token retrieved: ${AUTH_TOKEN}"
}

# Function to add target
add_target() {
    TARGET_ID=$(curl -sk -X POST "${BASE_URL}/api/v1/targets/add" \
        -H "Content-Type: application/json" \
        -H "X-Auth: ${AUTH_TOKEN}" \
        -H "Cookie: ui_session=${AUTH_TOKEN}" \
        -d '{"targets":[{"address":"'"${TARGET}"'","description":"Sent from Script"}],"groups":[]}' \
        | jq -r '.targets[0].target_id')
    if [ -z "${TARGET_ID}" ]; then
        echo "Unable to add target."
        exit 1
    fi
    echo "Target added: ${TARGET_ID}"
}

# Function to start scan
start_scan() {
    SCAN_PAYLOAD='{
        "profile_id":"'"${PROFILE_ID}"'",
        "incremental":false,
        "schedule":{
            "disable":false,
            "start_date":null,
            "time_sensitive":false
        },
        "report_template_id":"'"${REPORT_TEMPLATE_ID}"'",
        "target_id":"'"${TARGET_ID}"'"
    }'

    SCAN_ID=$(curl -sk -X POST "${BASE_URL}/api/v1/scans" \
        -H "Content-Type: application/json" \
        -H "X-Auth: ${AUTH_TOKEN}" \
        -H "Cookie: ui_session=${AUTH_TOKEN}" \
        -d "$SCAN_PAYLOAD" \
        | jq -r '.scan_id')
    if [ -z "${SCAN_ID}" ]; then
        echo "Unable to start scan."
        exit 1
    fi
    echo "Scan started: ${SCAN_ID}"
}

# Function to check scan status
check_scan_status() {
    while :; do
        STATUS=$(curl -sk -X GET "${BASE_URL}/api/v1/scans/${SCAN_ID}" \
            -H "X-Auth: ${AUTH_TOKEN}" \
            -H "Cookie: ui_session=${AUTH_TOKEN}" \
            | jq -r '.current_session.status')
        echo "Current scan status: ${STATUS}"
        if [[ "${STATUS}" =~ ^(aborted|paused|completed|failed)$ ]]; then
            break
        fi
        sleep 5
    done
    echo "Scan status: ${STATUS}"
}

# Function to get vulnerabilities
get_vulnerabilities() {
    SCAN_SESSION_ID=$(curl -sk -X GET "${BASE_URL}/api/v1/scans/${SCAN_ID}" \
        -H "X-Auth: ${AUTH_TOKEN}" \
        -H "Cookie: ui_session=${AUTH_TOKEN}" \
        | jq -r '.current_session.scan_session_id')
    
    VULNERABILITIES=$(curl -sk -X GET "${BASE_URL}/api/v1/scans/${SCAN_ID}/results/${SCAN_SESSION_ID}/vulnerabilities" \
        -H "X-Auth: ${AUTH_TOKEN}" \
        -H "Cookie: ui_session=${AUTH_TOKEN}" \
        | jq '.vulnerabilities')
    
    echo "Vulnerabilities: ${VULNERABILITIES}"
    
    # Check for any vulnerabilities
    if [ "$(echo "${VULNERABILITIES}" | jq -r '. | length')" -gt 0 ]; then
        CRITICAL_VULN_FOUND=1
    fi
}

# Function to generate report
generate_report() {
    REPORT_PAYLOAD='{
        "template_id": "11111111-1111-1111-1111-111111111111",
        "source": {
            "list_type": "scans",
            "id_list": ["'"${SCAN_ID}"'"]
        }
    }'

    # Print the curl command for debugging
    echo "curl -sk -X POST \"${BASE_URL}/api/v1/reports\" -H \"X-Auth: ${AUTH_TOKEN}\" -H \"Cookie: ui_session=${AUTH_TOKEN}\" -H \"Content-Type: application/json\" -d '${REPORT_PAYLOAD}'"

    response=$(curl -sk -X POST "${BASE_URL}/api/v1/reports" \
        -H "X-Auth: ${AUTH_TOKEN}" \
        -H "Cookie: ui_session=${AUTH_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$REPORT_PAYLOAD")

    report_id=$(echo $response | jq -r '.report_id')
    echo "$response"
    echo "Report ID: ${report_id}"

    # Wait until the report is generated
    while true; do
        report_response=$(curl -sk -X GET "${BASE_URL}/api/v1/reports/${report_id}" \
            -H "X-Auth: ${AUTH_TOKEN}" \
            -H "Cookie: ui_session=${AUTH_TOKEN}")
        
        report_status=$(echo $report_response | jq -r '.status')
        if [ "$report_status" != "completed" ]; then
            sleep 5
        else
            break
        fi
    done

    # Fetch the download link from the report response
    pdf_download_link=$(echo $report_response | jq -r '.download[1]')

    if [ -z "${pdf_download_link}" ]; then
        echo "[ERROR] No PDF found for report: ${report_id}"
        return
    fi

    mkdir -p reports
    filename=$(echo "${TARGET}" | sed 's/[^a-zA-Z0-9]/_/g')

    file="reports/report.pdf"
    curl -sk -X GET "${BASE_URL}${pdf_download_link}" \
        -H "X-Auth: ${AUTH_TOKEN}" \
        -H "Cookie: ui_session=${AUTH_TOKEN}" \
        --output "$file"
    echo "[INFO] Report ${file} generated successfully"
}

# Main Execution
get_auth_token
add_target
start_scan
check_scan_status
get_vulnerabilities
generate_report

# Exit with appropriate status
if [ ${CRITICAL_VULN_FOUND} -eq 1 ]; then
    echo "Vulnerabilities found. Failing the job."
    exit 1
else
    echo "No vulnerabilities found. Job passed."
    exit 0
fi
