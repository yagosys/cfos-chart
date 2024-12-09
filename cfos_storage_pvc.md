## when cfos deployed as "Deployment" with multiple replicas . all the cfos pod will share same data storage.

by default the helm chart will create a pvc and mount to cfos.


### install local-path storage class
```bash
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.26/deploy/local-path-storage.yaml
kubectl rollout status deployment local-path-provisioner -n local-path-storage
```
### check storageclass
```bash
kubectl get sc
```
result
```bash
NAME         PROVISIONER             RECLAIMPOLICY   VOLUMEBINDINGMODE      ALLOWVOLUMEEXPANSION   AGE
local-path   rancher.io/local-path   Delete
```

### default pvc 
when helm deploy with 

```bash
kubectl get pvc
```
result
```
NAME             STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   VOLUMEATTRIBUTESCLASS   AGE
cfosconfigdata   Bound    pvc-41089f66-37f4-4738-a2c0-3acc0a7e1382   1Gi        RWO            local-path     <unset>                 22s
```






