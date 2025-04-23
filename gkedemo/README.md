### deploy GKE 

```bash
./00_a_gcloud_env.sh
./00_create_network.sh
./01_gke.sh
./02_modifygkevmipforwarding.sh.shell.sh
```

### add label to worker node for deploy cFOS

```bash
kubectl get node
NAME                                                STATUS   ROLES    AGE    VERSION
gke-my-first-cluster-1-default-pool-63d106f1-xw2n   Ready    <none>   3m6s   v1.30.10-gke.1070000
kubectl label node gke-my-first-cluster-1-default-pool-63d106f1-xw2n security=true
node/gke-my-first-cluster-1-default-pool-63d106f1-xw2n labeled
kubectl get node -l security=true
NAME                                                STATUS   ROLES    AGE     VERSION
gke-my-first-cluster-1-default-pool-63d106f1-xw2n   Ready    <none>   3m33s   v1.30.10-gke.1070000
```

### get DNS ip address 
```bash
kubectl get svc kube-dns -n kube-system
NAME       TYPE        CLUSTER-IP    EXTERNAL-IP   PORT(S)         AGE
kube-dns   ClusterIP   10.144.0.10   <none>        53/UDP,53/TCP   6m19s
```

### create cFOS license configmap file
download license file from support.fortinet.com 
```bash
./generatecfoslicensefromvmlicense.sh  CFOSVLTMxxxxxx.lic
cfos_license.yaml created.
```

### deploy license configmap file

```bash
kubectl apply -f cfos_license.yaml 
configmap/fos-license created
kubectl get cm fos-license
NAME               DATA   AGE
fos-license        1      5s
```

### deploy cFOS with helm 

```bash
helm repo add cfos-chart https://yagosys.github.io/cfos-chart
helm repo update
helm search repo cfos-chart
helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos \
  --set routeManager.enabled=false \
  --set dnsConfig.nameserver=10.144.0.10 \
  --set-string nodeSelector.security="true" \
  --set appArmor.enabled=true 

```
output will be
```
helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos \
>   --set routeManager.enabled=false \
>   --set dnsConfig.nameserver=10.144.0.10 \
>   --set-string nodeSelector.security="true" \
>   --set appArmor.enabled=true 
Release "cfos7210250-deployment-new" does not exist. Installing it now.
W0423 23:25:54.483733    7913 warnings.go:70] spec.template.metadata.annotations[container.apparmor.security.beta.kubernetes.io/cfos]: deprecated since v1.30; use the "appArmorProfile" field instead
NAME: cfos7210250-deployment-new
LAST DEPLOYED: Wed Apr 23 23:25:48 2025
NAMESPACE: default
STATUS: deployed
REVISION: 1
NOTES:
1. Get the application URL by running these commands:
  export POD_NAME=$(kubectl get pods --namespace default -l "app.kubernetes.io/name=cfos,app.kubernetes.io/instance=cfos7210250-deployment-new" -o jsonpath="{.items[0].metadata.name}")
  export CONTAINER_PORT=$(kubectl get pod --namespace default $POD_NAME -o jsonpath="{.spec.containers[0].ports[0].containerPort}")
  echo "Visit http://127.0.0.1:8080 to use your application"
  kubectl --namespace default port-forward $POD_NAME 8080:$CONTAINER_PORT
```


### check cfos log
```bash
kubectl logs -f po/cfos7210250-deployment-new-75ddb9dbf4-fjgv8
Defaulted container "cfos" out of: cfos, init-myservice (init)

System is starting...

Firmware version is 7.2.1.0255
Preparing environment...
Verifying license...
INFO: 2025/04/23 23:26:05 importing license...
INFO: 2025/04/23 23:26:05 license is imported successfuly!
WARNING: System is running in restricted mode due to lack of valid license!
Starting services...
System is ready.

2025-04-23_23:26:08.46821 ok: run: /etc/services/certd: (pid 130) 5s, normally down
2025-04-23_23:26:13.53837 INFO: 2025/04/23 23:26:13 received a new fos configmap
2025-04-23_23:26:13.53839 INFO: 2025/04/23 23:26:13 configmap name: fos-license, labels: map[app:fos category:license]
2025-04-23_23:26:13.53839 INFO: 2025/04/23 23:26:13 got a fos license
```

###
```bash

kubectl exec -it po/cfos7210250-deployment-new-75ddb9dbf4-fjgv8 -- /bin/cli
Defaulted container "cfos" out of: cfos, init-myservice (init)
User: admin
Password: 
cFOS # execute update-now 
....
cFOS # diagnose sys license

Status: Valid license
SN: CFOSVLTM24000025
Valid From: 2025-02-14
Valid To: 2025-06-21

```
