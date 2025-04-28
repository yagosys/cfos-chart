gcloud compute networks create gkenetwork --subnet-mode custom --bgp-routing-mode  regional 
gcloud compute networks subnets create gkenode --network=gkenetwork --range=10.0.0.0/24 
gcloud compute firewall-rules create gkenetwork-allow-custom --network gkenetwork --allow all --direction ingress --priority  100 
