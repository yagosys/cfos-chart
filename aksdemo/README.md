## prepare cfos license 

copy license configmap file or use ./akscfosdemo.sh createcFOSlicensefile to generate one
```
ls cfos_license.yaml 
cfos_license.yaml
```


## run demo 


```bash
./akscfosdemo.sh createAKScluster
./akscfosdemo.sh demo
```

## send attack traffic to check log

```bash
./akscfosdemo.sh 
❌ wrong command
  demo                                - demo
  createAKScluster                    - create GKE cluster
  addlabel                            - add node app=true and security=true to each node
  deployDemoPod                       - Deploy protected demo application pod and check connectivity
  applyCFOSLicense                    - Apply cFOS licene file cfos_license.yaml
  createcFOSlicensefile               - create cFOS licenseconfigmap file from .lic file
  deploycFOSwithAgent                 - Deploy CFOS and vxlan agent with helm chart
  createIngressDemo                   - createIngressDemo for juiceshop
  sendAttacktocFOSheadlesssvc         - send attack to cFOSheadlesssvc for ingress security test
  sendWebftoExternal                  - send webf to external for egress security test
  sendAttackToClusterIP               - send attack traffic to clusterip svc for egress security test
```


