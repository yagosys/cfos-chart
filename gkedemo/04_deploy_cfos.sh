
#gcloud container clusters get-credentials  my-first-cluster-1 --zone us-central1-a

kube_dns_ip=$(kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}')

helm repo add cfos-chart https://yagosys.github.io/cfos-chart
helm repo update
helm search repo cfos-chart
helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos \
  --set routeManager.enabled=false \
  --set dnsConfig.nameserver=$kube_dns_ip \
  --set-string nodeSelector.security="true" \
  --set appArmor.enabled=true

kubectl rollout status deployment cfos7210250-deployment-new
