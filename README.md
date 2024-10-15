##################################
below is a full example which use cfos chart to demo cFOS egress security with eks cluster 

## Deploy cfos and agent 
## Bring up EKS cluster
- worker with label app=true
- worker with label security=true

```bash
#!/bin/bash -xe

AWS_REGION="us-east-1"
EKSVERSION="1.30"
CLUSTERNAME="democluster"
PODCIDR="10.244.0.0/16"
AVAILABILITY_ZONES=$(aws ec2 describe-availability-zones --region $AWS_REGION --query "AvailabilityZones[?State=='available'].ZoneName" --output text | tr '\t' ',' | cut -d',' -f1-2)
filename="way3cluster.yaml"

cat << EOF | tee > $filename
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
availabilityZones: [$(echo $AVAILABILITY_ZONES | tr ',' '\n' | sed 's/^/"/' | sed 's/$/"/' | paste -sd ',' -)]
metadata:
  version: "${EKSVERSION}"
  name: $CLUSTERNAME
  region: $AWS_REGION
  tags:
    owner: wandy
iam:
  withOIDC: true

managedNodeGroups:
  - name: ${CLUSTERNAME}-eks-ng-app
    labels:
      nodegroup-type: external
      role: worker
      app: "true"
    instanceType: t2.large
    desiredCapacity: 1
    minSize: 0
    maxSize: 3
    tags:
      nodegrouprole: ${CLUSTERNAME}
    volumeSize: 100
    iam:
      withAddonPolicies:
        externalDNS: true
        certManager: true
        awsLoadBalancerController: true
        albIngress: true
        ebs: false
        efs: false
        imageBuilder: false
        cloudWatch: true
    privateNetworking: true
    preBootstrapCommands:
      - "echo test"
    ssh:
      allow: true # will use ~/.ssh/id_rsa.pub as the default ssh key
      enableSsm: true

  - name: ${CLUSTERNAME}-eks-ng-security
    labels:
      nodegroup-type: external
      role: worker
      security: "true"
    instanceType: t2.large
    desiredCapacity: 1
    minSize: 0
    maxSize: 3
    tags:
      nodegrouprole: ${CLUSTERNAME}
    volumeSize: 100
    iam:
      withAddonPolicies:
        externalDNS: true
        certManager: true
        awsLoadBalancerController: true
        albIngress: true
        ebs: false
        efs: false
        imageBuilder: false
        cloudWatch: true
    privateNetworking: true
    preBootstrapCommands:
      - "echo test"
    ssh:
      allow: true # will use ~/.ssh/id_rsa.pub as the default ssh key
      enableSsm: true

kubernetesNetworkConfig:
  ipFamily: IPv4
  serviceIPv4CIDR: 10.96.0.0/16

vpc:
  autoAllocateIPv6: false
  cidr: ${PODCIDR}
  clusterEndpoints:
    privateAccess: true
    publicAccess: true
  nat:
    gateway: HighlyAvailable # other options: Disable, Single (default) ,HighlyAvailable

accessConfig:
  bootstrapClusterCreatorAdminPermissions: true # default is true
  authenticationMode: API 
EOF

eksctl get cluster --name $CLUSTERNAME --region $AWS_REGION || eksctl create cluster -f $filename
aws eks create-addon --addon-name eks-pod-identity-agent --cluster ${CLUSTERNAME} --addon-version v1.0.0-eksbuild.1 --region $AWS_REGION
kubectl get pods -n kube-system | grep 'eks-pod-identity-agent' || true
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
aws eks list-access-entries --cluster-name ${CLUSTERNAME} --region $AWS_REGION

```
### Verify  the cluster 
```bash
kubectl get node -l app=true
```
result
```
NAME                             STATUS   ROLES    AGE    VERSION
ip-10-244-103-112.ec2.internal   Ready    <none>   3m6s   v1.30.4-eks-a737599
```
```bash
kubectl get node -l security=true
```
result
```
NAME                             STATUS   ROLES    AGE     VERSION
ip-10-244-117-209.ec2.internal   Ready    <none>   2m37s   v1.30.4-eks-a737599
```

## install cfos DaemonSet and agent 
```bash
helm repo add cfos-chart https://yagosys.github.io/cfos-chart
helm repo update
helm search repo cfos-chart
helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos --set appArmor.enabled=true
```

### verify the deployment
```
helm list
```
result
```
NAME                      	NAMESPACE	REVISION	UPDATED                             	STATUS  	CHART     	APP VERSION
cfos7210250-deployment-new	default  	1       	2024-10-14 15:54:40.697525 -0500 CDT	deployed	cfos-0.1.3	7.2.1.257
```

```bash
kubectl get pod
```
result
```
NAME                               READY   STATUS    RESTARTS   AGE
cfos7210250-deployment-new-5x9tc   1/1     Running   0          54s
route-manager-6v9g9                1/1     Running   0          54s
route-manager-zfmsh                1/1     Running   0          54s

```
## apply cfos license via configmap file
```bash
kubectl apply -f cfos_license.yaml
```

### Verify the license import 
```bash
podname=$(kubectl get pod -l app=firewall -o jsonpath='{.items[0].metadata.name}')
kubectl logs -f po/$podname -c cfos
```
result
```

System is starting...

Firmware version is 7.2.1.0255
Preparing environment...
Verifying license...
WARNING: System is running in restricted mode due to lack of valid license!
Starting services...
System is ready.

2024-10-14_22:47:50.11804 ok: run: /etc/services/certd: (pid 131) 2s, normally down
2024-10-14_22:48:07.55389 INFO: 2024/10/14 22:48:07 received a new fos configmap
2024-10-14_22:48:07.55390 INFO: 2024/10/14 22:48:07 configmap name: fos-license, labels: map[app:fos category:license]
2024-10-14_22:48:07.55390 INFO: 2024/10/14 22:48:07 got a fos license
2024-10-14_22:48:07.55390 INFO: 2024/10/14 22:48:07 importing license...
2024-10-14_22:48:07.56238 INFO: 2024/10/14 22:48:07 license is imported successfuly!
2024-10-14_22:48:21.23682 ok: run: /etc/services/certd: (pid 131) 33s, normally down
2024-10-14_22:48:26.28280 INFO: 2024/10/14 22:48:26 received a new fos configmap
2024-10-14_22:48:26.28280 INFO: 2024/10/14 22:48:26 configmap name: fos-license, labels: map[app:fos category:license]
2024-10-14_22:48:26.28280 INFO: 2024/10/14 22:48:26 got a fos license

```
## create firewall policy via configmap file

```bash
filename="net1tointernetfirewallpolicy.yaml"
cat << 'EOF' | tee > $filename
apiVersion: v1
kind: ConfigMap
metadata:
  name: vxlan0tointernet
  labels:
      app: fos
      category: config
data:
  type: partial
  config: |-
    config webfilter content
       edit 1
         set name "webfilter"
          config entries
            edit "fortinet"
             set pattern-type regexp
             set status enable
             set lang western
             set score 10
             set action block
            next
          end
       next
    end
    config webfilter profile
         edit "webfilter"
           config web
              set bword-threshold 10
              set bword-table 1
           end
           config ftgd-wf
              unset options
              config filters
                  edit 1
                      set category 26
                      set action block
                  next
              end
           end
         next
         edit "default"
           set log-all-url enable
           set extended-log enable
         next
    end
    config application list
      edit "default"
        set comment "Monitor all applications."
        set extended-log enable
          config entries
             edit 1
                set category 5
                set action block
             next
          end
      next
    end
    config firewall ssl-ssh-profile
       edit "mytest"
           config https
             set expired-server-cert allow
             set revoked-server-cert allow
             set cert-validation-failure allow
             set sni-server-cert-check disable
             set cert-probe-failure allow
           end
           set caname "Device"
           set untrusted-caname "Device"
       next
    end
    config firewall policy
        edit 100
            set utm-status enable
            set name "vxlan0tointernet"
            set srcintf "vxlan0"
            set dstintf "eth0"
            set srcaddr "all"
            set dstaddr "all"
            set service "ALL"
            set ssl-ssh-profile "mytest"
            set av-profile "default"
            set ips-sensor "high_security"
            set application-list "default"
            set webfilter-profile "webfilter"
            set nat enable
            set logtraffic all
        next
    end
EOF
kubectl apply -f $filename

```
### Verify the firewall policy

```bash
podname=$(kubectl get pod -l app=firewall -o jsonpath='{.items[0].metadata.name}')
kubectl exec -it po/$podname -c cfos -- more /data/cmdb/config/firewall/policy.json
```
result
```
[
    {
        "policyid": 100,
        "status": "enable",
        "utm-status": "enable",
        "name": "vxlan0tointernet",
        "comments": "",
        "srcintf": [
            "vxlan0"
        ],
        "dstintf": [
            "eth0"
        ],
        "srcaddr": [
            "all"
        ],
        "dstaddr": [
            "all"
        ],
        "srcaddr6": [],
        "dstaddr6": [],
        "service": [
            "ALL"
        ],
        "ssl-ssh-profile": "mytest",
        "profile-type": "single",
        "profile-group": "",
        "profile-protocol-options": "default",
        "av-profile": "default",
        "webfilter-profile": "webfilter",
        "ips-sensor": "high_security",
        "application-list": "default",
        "action": "accept",
        "nat": "enable",
        "custom-log-fields": [],
        "logtraffic": "all"
    }
]%
```
## create procted application pod with label protectedby=cfos 
```bash
filename="protectedpod.yaml"
cat <<EOF | tee > $filename
apiVersion: apps/v1
kind: Deployment
metadata:
  name: diag
  labels:
    app: diag
    cfos: protected
spec:
  replicas: 1
  selector:
    matchLabels:
      app: diag
  template:
    metadata:
      labels:
        app: diag
        protectedby: cfos
    spec:
      nodeSelector:
        app: "true"
      containers:
      - name: diag
        image: praqma/network-multitool:latest
        securityContext:
          privileged: false

EOF
kubectl apply -f $filename

```
### check protected application deployment
```bash
kubectl get pod -l protectedby=cfos
```
result
```
NAME                    READY   STATUS    RESTARTS   AGE
diag-5bc9c56477-tclq9   1/1     Running   0          22s
```
## check procted pod whether able to reach internet through cFOS as nexthop
```bash
filename="pingalltest.sh"
cat << 'EOF' | tee > $filename
#!/bin/bash

pods=$(kubectl get pods -l protectedby=cfos -o jsonpath='{.items[*].metadata.name}')

for pod in $pods; do
    echo "Running ping in pod: $pod"
    if kubectl exec $pod -- /bin/sh -c 'ping -c 1 -W 5 1.1.1.1 > /dev/null 2>&1'; then
        echo "Ping succeeded in pod: $pod"
    else
        echo "Ping failed in pod: $pod"
        echo "Attempting manual ping for debugging:"
        kubectl exec $pod -- ping -c 2 1.1.1.1
    fi
    echo "---"
done

echo "Ping completed in all pods to address 1.1.1.1."
EOF
chmod +x $filename
./$filename

```
## scale protected pod to more numbers 
```bash
kubectl scale deployment diag --replicas=20
```
### verify scale 
```bash
kubectl get deployment diag
```

```
NAME   READY   UP-TO-DATE   AVAILABLE   AGE
diag   20/20   20           20          4m24s
```

## Check all protected pod for connectivites
```bash
./pingalltest.sh
```

## scale application node
scale worker node for create more protected pod 

```bash
eksctl scale nodegroup democluster-eks-ng-app -N 2 --cluster $CLUSTERNAME
```
result
```
2024-10-15 08:06:34 [ℹ]  scaling nodegroup "democluster-eks-ng-app" in cluster democluster
2024-10-15 08:06:38 [ℹ]  initiated scaling of nodegroup
2024-10-15 08:06:38 [ℹ]  to see the status of the scaling run `eksctl get nodegroup --cluster $CLUSTERNAME --region us-east-1 --name democluster-eks-ng-app`
kubectl get node
NAME                             STATUS   ROLES    AGE   VERSION
ip-10-244-103-112.ec2.internal   Ready    <none>   17m   v1.30.4-eks-a737599
ip-10-244-117-209.ec2.internal   Ready    <none>   17m   v1.30.4-eks-a737599
ip-10-244-69-56.ec2.internal     Ready    <none>   31s   v1.30.4-eks-a737599
kubectl get node -l app=true
NAME                             STATUS   ROLES    AGE   VERSION
ip-10-244-103-112.ec2.internal   Ready    <none>   17m   v1.30.4-eks-a737599
ip-10-244-69-56.ec2.internal     Ready    <none>   40s   v1.30.4-eks-a737599


```

## scale protected pod to more numbers 
```bash
kubectl scale deployment diag --replicas=60
```

```bash
kubectl get deployment diag
```
result
```
NAME   READY   UP-TO-DATE   AVAILABLE   AGE
diag   60/60   60           60          10m
```

## check connectivity again

```bash
./pingalltest.sh
```
### Result
```bash
./pingalltest.sh
Running ping in pod: diag-5bc9c56477-24hzl
Ping succeeded in pod: diag-5bc9c56477-24hzl
---
Running ping in pod: diag-5bc9c56477-2d2lc
Ping succeeded in pod: diag-5bc9c56477-2d2lc
....
....
....

---
Ping completed in all pods to address 1.1.1.1.

```

## test with real attack traffic

```bash
filename="cfos_test_traffic.sh"
cat << 'EOF' | tee > $filename
#!/bin/bash -xe
while true; do
    # Get all pods with label protectedby=cfos
    pods=$(kubectl get pod -l protectedby=cfos -o custom-columns=NAME:.metadata.name --no-headers)

    for pod in $pods; do
        (
            printf "\e[1;32m   Running tests on pod: $pod \e[0m\n"

            printf "\e[1;32m   Test IPS feature for egress traffic \e[0m\n"
            kubectl exec -it "$pod" -- sh -c "curl -k --max-time 5 -H \"User-Agent: () { :; }; /bin/ls\" https://ipinfo.io" || true
            sleep 1

            printf "\e[1;32m   Test application control feature for egress traffic \e[0m\n"
            kubectl exec -it "$pod"  -- sh -c "curl -k https://www.youtube.com" || true
            sleep 1

            printf "\e[1;32m   Test web filter feature for egress traffic \e[0m\n"
            kubectl exec -it "$pod" -- sh -c "curl -k https://www.fortiguard.com/wftest/26.html" || true
            sleep 1

            printf "\e[1;32m   Test web content filter feature for egress traffic \e[0m\n"
            kubectl exec -it "$pod" -- sh -c "curl -k https://www.fortiguard.com/psirt" || true
            sleep 1

            printf "\e[1;32m   Test download EICAR test file \e[0m\n"
            kubectl exec -it "$pod" -- sh -c "wget -c https://secure.eicar.org/eicar_com.zip --no-check-certificate" || true
        ) 
    done


    # Wait for 5 seconds before the next iteration
    echo "Waiting for 5 seconds..."
    sleep 5
done

EOF
chmod +x $filename
./$filename

```
### Check Result log

```bash
kubectl get pod -l app=firewall
NAME                               READY   STATUS    RESTARTS      AGE
cfos7210250-deployment-new-5x9tc   1/1     Running   1 (39m ago)   41m
```
```bash
podname=$(kubectl get pod -l app=firewall -o jsonpath='{.items[0].metadata.name}')
kubectl exec -it po/$podname -c cfos -- sh

# cd /var/log/log/
# ls app.0
app.0
# ls -l app.0
-rw-------    1 root     root          1518 Oct 14 21:30 app.0
# ls -l webf.0
-rw-------    1 root     root          5029 Oct 14 21:30 webf.0
# ls -l ips.0
-rw-------    1 root     root         33036 Oct 14 21:31 ips.0
# more app.0
date=2024-10-14 time=21:29:54 eventtime=1728941394 tz="+0000" logid="1059028705" type="utm" subtype="app-ctrl" eventtype="signature" level="warning" appid=31077 srcip=192.168.200.197 dstip=142.251.16.91 srcport=54688 dstport=443 srcintf="vxlan0" dstintf="eth0" proto=6 service="SSL" direction="outgoing" policyid=100 sessionid=489 applist="default" action="block" appcat="Video/Audio" app="YouTube" hostname="www.youtube.com" incidentserialno=89129505 url="/" msg="Video/Audio: YouTube" apprisk="elevated"
date=2024-10-14 time=21:30:21 eventtime=1728941421 tz="+0000" logid="1059028705" type="utm" subtype="app-ctrl" eventtype="signature" level="warning" appid=31077 srcip=192.168.200.107 dstip=142.251.16.91 srcport=35432 dstport=443 srcintf="vxlan0" dstintf="eth0" proto=6 service="SSL" direction="outgoing" policyid=100 sessionid=525 applist="default" action="block" appcat="Video/Audio" app="YouTube" hostname="www.youtube.com" incidentserialno=89129541 url="/" msg="Video/Audio: YouTube" apprisk="elevated"
date=2024-10-14 time=21:30:46 eventtime=1728941446 tz="+0000" logid="1059028705" type="utm" subtype="app-ctrl" eventtype="signature" level="warning" appid=31077 srcip=192.168.200.68 dstip=142.251.163.91 srcport=58258 dstport=443 srcintf="vxlan0" dstintf="eth0" proto=6 service="SSL" direction="outgoing" policyid=100 sessionid=561 applist="default" action="block" appcat="Video/Audio" app="YouTube" hostname="www.youtube.com" incidentserialno=89129578 url="/" msg="Video/Audio: YouTube" apprisk="elevated"
# more webf.0
date=2024-10-14 time=21:29:59 eventtime=1728941399 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" policyid=100 sessionid=496 srcip=192.168.200.197 srcport=53068 srcintf="vxlan0" dstip=154.52.3.165 dstport=443 dstintf="eth0" proto=6 service="HTTPS" hostname="www.fortiguard.com" profile="webfilter" action="blocked" reqtype="direct" url="https://www.fortiguard.com/wftest/26.html" sentbyte=128 rcvdbyte=36 direction="outgoing" msg="URL belongs to a denied category in policy" method="domain" cat=26 catdesc="Malicious Websites"
date=2024-10-14 time=21:30:04 eventtime=1728941404 tz="+0000" logid="0314012288" type="utm" subtype="webfilter" eventtype="content" level="warning" policyid=100 sessionid=503 srcip=192.168.200.197 srcport=47348 srcintf="vxlan0" dstip=154.52.3.165 dstport=443 dstintf="eth0" proto=6 service="HTTPS" hostname="www.fortiguard.com" profile="webfilter" reqtype="direct" url="https://www.fortiguard.com/psirt" sentbyte=122 rcvdbyte=4506 direction="outgoing" action="blocked" msg="URL was blocked because it contained banned word(s)."
date=2024-10-14 time=21:30:09 eventtime=1728941409 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" policyid=100 sessionid=511 srcip=192.168.200.197 srcport=56766 srcintf="vxlan0" dstip=89.238.73.97 dstport=443 dstintf="eth0" proto=6 service="HTTPS" hostname="secure.eicar.org" profile="webfilter" action="blocked" reqtype="direct" url="https://secure.eicar.org/eicar_com.zip" sentbyte=144 rcvdbyte=0 direction="outgoing" msg="URL belongs to a denied category in policy" method="domain" cat=26 catdesc="Malicious Websites"
date=2024-10-14 time=21:30:25 eventtime=1728941425 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" policyid=100 sessionid=532 srcip=192.168.200.107 srcport=45116 srcintf="vxlan0" dstip=154.52.3.165 dstport=443 dstintf="eth0" proto=6 service="HTTPS" hostname="www.fortiguard.com" profile="webfilter" action="blocked" reqtype="direct" url="https://www.fortiguard.com/wftest/26.html" sentbyte=119 rcvdbyte=0 direction="outgoing" msg="URL belongs to a denied category in policy" method="domain" cat=26 catdesc="Malicious Websites"
date=2024-10-14 time=21:30:29 eventtime=1728941429 tz="+0000" logid="0314012288" type="utm" subtype="webfilter" eventtype="content" level="warning" policyid=100 sessionid=539 srcip=192.168.200.107 srcport=45120 srcintf="vxlan0" dstip=154.52.3.165 dstport=443 dstintf="eth0" proto=6 service="HTTPS" hostname="www.fortiguard.com" profile="webfilter" reqtype="direct" url="https://www.fortiguard.com/psirt" sentbyte=122 rcvdbyte=4505 direction="outgoing" action="blocked" msg="URL was blocked because it contained banned word(s)."
date=2024-10-14 time=21:30:34 eventtime=1728941434 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" policyid=100 sessionid=547 srcip=192.168.200.107 srcport=51976 srcintf="vxlan0" dstip=89.238.73.97 dstport=443 dstintf="eth0" proto=6 service="HTTPS" hostname="secure.eicar.org" profile="webfilter" action="blocked" reqtype="direct" url="https://secure.eicar.org/eicar_com.zip" sentbyte=144 rcvdbyte=0 direction="outgoing" msg="URL belongs to a denied category in policy" method="domain" cat=26 catdesc="Malicious Websites"
date=2024-10-14 time=21:30:50 eventtime=1728941450 tz="+0000" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" policyid=100 sessionid=568 srcip=192.168.200.68 srcport=37836 srcintf="vxlan0" dstip=154.52.3.165 dstport=443 dstintf="eth0" proto=6 service="HTTPS" hostname="www.fortiguard.com" profile="webfilter" action="blocked" reqtype="direct" url="https://www.fortiguard.com/wftest/26.html" sentbyte=119 rcvdbyte=0 direction="outgoing" msg="URL belongs to a denied category in policy" method="domain" cat=26 catdesc="Malicious Websites"
date=2024-10-14 time=21:30:55 eventtime=1728941455 tz="+0000" logid="0314012288" type="utm" subtype="webfilter" eventtype="content" # more ips.0
date=2024-10-14 time=21:27:32 eventtime=1728941252 tz="+0000" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="critical" srcip=192.168.200.219 dstip=34.117.59.81 srcintf="vxlan0" dstintf="eth0" sessionid=87 action="dropped" proto=6 service="HTTPS" policyid=100 attack="Bash.Function.Definitions.Remote.Code.Execution" srcport=33466 dstport=443 hostname="ipinfo.io" url="/" direction="outgoing" attackid=39294 profile="high_security" incidentserialno=89129061 msg="applications3: Bash.Function.Definitions.Remote.Code.Execution"
date=2024-10-14 time=21:27:32 eventtime=1728941252 tz="+0000" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="critical" srcip=192.168.200.197 dstip=34.117.59.81 srcintf="vxlan0" dstintf="eth0" sessionid=114 action="dropped" proto=6 service="HTTPS" policyid=100 attack="Bash.Function.Definitions.Remote.Code.Execution" srcport=57630 dstport=443 hostname="ipinfo.io" url="/" direction="outgoing" attackid=39294 profile="high_security" incidentserialno=89129090 msg="applications3: Bash.Function.Definitions.Remote.Code.Execution"
date=2024-10-14 time=21:27:32 eventtime=1728941252 tz="+0000" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="critical" srcip=192.168.200.157 dstip=34.117.59.81 srcintf="vxlan0" dstintf="eth0" sessionid=115 action="dropped" proto=6 service="HTTPS" policyid=100 attack="Bash.Function.Definitions.Remote.Code.Execution" srcport=49388 dstport=443 hostname="ipinfo.io" url="/" direction="outgoing" attackid=39294 profile="high_security" incidentserialno=89129096 msg="applications3: Bash.Function.Definitions.Remote.Code.Execution"
date=2024-10-14 time=21:27:32 eventtime=1728941252 tz="+0000" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="critical" srcip=192.168.200.27 dstip=34.117.59.81 srcintf="vxlan0" dstintf="eth0" sessionid=124 action="dropped" proto=6 service="HTTPS" policyid=100 attack="Bash.Function.Definitions.Remote.Code.Execution" srcport=57940 dstport=443 hostname="ipinfo.io" url="/" direction="outgoing" attackid=39294 profile="high_security" incidentserialno=89129105 msg="applications3: Bash.Function.Definitions.Remote.Code.Execution"
date=2024-10-14 time=21:27:32 eventtime=1728941252 tz="+0000" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="critical" srcip=192.168.200.91 dstip=34.117.59.81 srcintf="vxlan0" dstintf="eth0" sessionid=132 action="dropped" proto=6 service="HTTPS" policyid=100 attack="Bash.Function.Definitions.Remote.Code.Execution" srcport=38028 dstport=443 hostname="ipinfo.io" url="/" direction="outgoing" attackid=39294 profile="high_security" incidentserialno=89129126 msg="applications3: Bash.Function.Definitions.Remote.Code.Execution"
date=2024-10-14 time=21:27:32 eventtime=1728941252 tz="+0000" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="critical" srcip=192.168.200.44 dstip=34.117.59.81 srcintf="vxlan0" dstintf="eth0" sessionid=138 action="dropped" proto=6 service="HTTPS" policyid=100 attack="Bash.Function.Definitions.Remote.Code.Execution" srcport=41406 dstport=443 hostname="ipinfo.io" url="/" direction="outgoing" attackid=39294 profile="high_security" incidentserialno=89129129 msg="applications3: Bash.Function.Definitions.Remote.Code.Execution"
date=2024-10-14 time=21:27:32 eventtime=1728941252 tz="+0000" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="critical" srcip=192.168.200.64 dstip=34.117.59.81 srcintf="vxlan0" dstintf="eth0" sessionid=133 action="dropped" proto=6 service="HTTPS" policyid=100 attack="Bash.Function.Definitions.Remote.Code.Execution" srcport=58336 dstport=443 hostname="ipinfo.io" url="/" direction="outgoing" attackid=39294 profile="high_security" incidentserialno=89129130 msg="applications3: Bash.Fun#
```
## uninstall cFOS

```bash
helm list 
helm uninstall cfos7210250-deployment-new 
```

## remove protected pod

```bash
kubectl delete deployment diag
```

## remove eks cluster

```bash
eksclt delete cluster --name $CLUSTERNAME
```
