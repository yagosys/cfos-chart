location="westus"
resourcegroupname="demofortiwebingresscontroller"

az group create --location $location --resource-group $resourcegroupname

[ ! -f ~/.ssh/id_rsa ] && ssh-keygen -q -N "" -f ~/.ssh/id_rsa

clustername=$(whoami)-aks-cluster
WINDOWS_USERNAME='azureuser'
WINDOWS_PASSWORD='Welcome.123456!#'
#INSTANCETYPE="Standard_D4s_v4" #4vcpu ,16G memory
INSTANCETYPE="Standard_D2s_v4" #2vcpu ,8G memory
PUBLICIPNAME="myvmpublicip" 

az aks create \
    --resource-group $resourcegroupname \
    --name ${clustername} \
    --node-count 1 \
    --enable-addons monitoring \
    --windows-admin-username $WINDOWS_USERNAME \
    --windows-admin-password $WINDOWS_PASSWORD \
    --node-vm-size $INSTANCETYPE \
    --vm-set-type VirtualMachineScaleSets \
    --network-plugin azure \
    --service-cidr  10.96.0.0/16 \
    --dns-service-ip 10.96.0.10 \
    --nodepool-name worker \
    --nodepool-labels nested=true linux=true

# --load-balancer-sku standard \

#az aks nodepool add \
#    --resource-group $resourcegroupname \
#    --cluster-name ${clustername} \
#    --os-type Linux \
#    --node-vm-size $INSTANCETYPE \
#    --name ubuntu \
#    --labels nested=true linux=true \
#    --node-count 1 
#
#az network public-ip create \
#    --resource-group $resourcegroupname \
#    --name $PUBLICIPNAME \
#    --sku Standard \
#    --allocation-method static
#
#az network public-ip show --resource-group $resourcegroupname --name $PUBLICIPNAME --query ipAddress --output tsv
#
CLIENT_ID=$(az aks show --name $clustername --resource-group $resourcegroupname --query identity.principalId -o tsv)
RG_SCOPE=$(az group show --name $resourcegroupname --query id -o tsv)
az role assignment create \
    --assignee ${CLIENT_ID} \
    --role "Network Contributor" \
    --scope ${RG_SCOPE}

##update kubeconfig file for kubectl to use 

az aks get-credentials -g  $resourcegroupname -n ${clustername} --overwrite-existing
