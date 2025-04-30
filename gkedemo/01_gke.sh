#!/bin/bash -xe
[[ $defaultClustername == "" ]] && defaultClustername="my-first-cluster-1"
[[ $networkName == "" ]] && networkName="gkenetwork"
[[ $subnetName == "" ]] && subnetName="gkenode"
[[ $machineType == "" ]] && machineType="e2-standard-2"
[[ $num_nodes == "" ]] && num_nodes="2"
[[ $services_ipv4_cidr == "" ]] && services_ipv4_cidr="10.144.0.0/20"
[[ $cluster_ipv4_cidr == "" ]] && cluster_ipv4_cidr="10.140.0.0/14"
#[[ $cluster_version == "" ]] && cluster_version=$(gcloud container get-server-config --zone us-central1-a --format=json | jq 'first(.validMasterVersions[] | select(startswith("1.26.5")))')

cluster_version="1.30.10-gke.1070000"


filename="01_gke.sh.gen.sh"

gkeClusterName=$defaultClustername
machineType=$machineType
gkeNetworkName=$(gcloud compute networks list --format="value(name)" --filter="name="$networkName""  --limit=1)
gkeSubnetworkName=$(gcloud compute networks subnets  list --format="value(name)" --filter="name="$subnetName"" --limit=1)

cat << EOF > $filename
projectName=\$(gcloud config list --format="value(core.project)")
region=\$(gcloud config get compute/region)

gcloud services enable container.googleapis.com  && \

gcloud container clusters create $gkeClusterName  \
	--no-enable-basic-auth \
	--cluster-version $cluster_version \
	--release-channel "stable" \
	--machine-type $machineType \
	--image-type "UBUNTU_CONTAINERD" \
	--disk-type "pd-balanced" \
	--disk-size "64" \
	--metadata disable-legacy-endpoints=true \
	--scopes "https://www.googleapis.com/auth/devstorage.read_only","https://www.googleapis.com/auth/logging.write","https://www.googleapis.com/auth/monitoring","https://www.googleapis.com/auth/servicecontrol","https://www.googleapis.com/auth/service.management.readonly","https://www.googleapis.com/auth/trace.append" \
	--max-pods-per-node "110" \
	--num-nodes $num_nodes \
	--enable-ip-alias \
	--network "projects/$projectName/global/networks/$gkeNetworkName" \
	--subnetwork "projects/$projectName/regions/$region/subnetworks/$gkeSubnetworkName" \
       	--no-enable-intra-node-visibility \
	--default-max-pods-per-node "110" \
	--no-enable-master-authorized-networks \
	--addons HorizontalPodAutoscaling,HttpLoadBalancing,GcePersistentDiskCsiDriver \
	--enable-autoupgrade \
	--enable-autorepair \
       	--max-surge-upgrade 1 \
	--max-unavailable-upgrade 0 \
	--enable-shielded-nodes \
        --enable-network-policy \
	--services-ipv4-cidr $services_ipv4_cidr \
        --cluster-ipv4-cidr  $cluster_ipv4_cidr || echo cluster creation failed
EOF
chmod +x $filename


./$filename
echo done
echo cluster has podIpv4CidrBlock $(gcloud container clusters describe $gkeClusterName --format="value(nodePools.networkConfig.podIpv4CidrBlock)")
echo cluster has servicesIpv4Cidr $(gcloud container clusters describe $gkeClusterName --format="value(servicesIpv4Cidr)")


clustersearchstring=$(gcloud container clusters list --format="value(name)" --limit=1)
name=$(gcloud compute instances list --filter="name~'$clustersearchstring'"  --format="value(name)" --limit=1)
echo cluster worker node vm has internal ip $(gcloud compute instances describe $name --format="value(networkInterfaces.aliasIpRanges)" --format="value(networkInterfaces.networkIP)")
echo cluster worker node vm has alias ip $(gcloud compute instances describe $name  --format="value(networkInterfaces.aliasIpRanges)")
