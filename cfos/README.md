## install chart

```bash
helm repo add cfos-chart https://yagosys.github.io/cfos-chart
helm repo update
helm search repo cfos-chart
```

## deploy cfos without agent and use nodeSeelector label

the helm chart by default only deploy to node with lable "security=true". 

if your node do not have label "security=true". then label it first or use --set-string to use your own label  

```bash
helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos \
  --set routeManager.enabled=false \
  --set dnsConfig.nameserver=10.144.0.10 \
  --set-string nodeSelector.security="true" \
```

##  deploy cfos and agent

```bash
helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos --set dnsConfig.nameserver=<your kubernetes dns service ip>
```

##  deploy cfos without routeManager agent

```bash
helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos   --set routeManager.enabled=false --set dnsConfig.nameserver=<your kubernetes dns service ip>
```

## check detail of chart

```
helm show all cfos-chart/cfos
helm manifest cfos7210250-deployment-new 
```

## deploy with argument

- HPA 

```bash
helm install/upgrade ... --set deployment.kind=Deployment,autoscaling.enabled=true
```
- enable appArmor

```bash
helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos --set appArmor.enabled=true
```
## Deploy with keda and sample metrics configmap

```bash
helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos --set kedaScaling.enabled=true --set cFOSmetricExample.enabled=true
```

## Deploy with custom vxlan port for routeManager agent and other parameters
in case use calico CNI with vxlan mode, need change routemanager default vxlan_port to something else like 4444. 

```bash
ROUTE_DST="1.0.0.0/1\,128.0.0.0/1" #traffic to these will be route to cFOS
CLUSTER_ROUTE_DST="1.2.3.4/32\,5.6.7.8/32" #traffic to these address will bypass cFOS
POLICY="UTM"
storageClass="microk8s-hostpath"

helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos  --set appArmor.enabled=true --set routeManager.image.tag=cni0.1.25clusteroute --set routeManager.env.VXLAN_PORT=4444 --set dnsConfig.nameserver=$dnsclusterip --set routeManager.image.pullPolicy=Always --set resources.requests.cpu=100m --set-string routeManager.env.ROUTE_DST=$ROUTE_DST --set routeManager.env.DEFAULT_FIREWALL_POLICY=$POLICY --set-string routeManager.env.CLUSTER_ROUTE_DST=$CLUSTER_ROUTE_DST --set persistence.storageClass=$storageClass --set persistence.enabled=false
```
