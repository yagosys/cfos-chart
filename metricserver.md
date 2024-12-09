## metric server on router-manager agent 

### service 
```bash
kubectl get svc cfos7210250-deployment-new-metrics
```
result
```
NAME                                 TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
cfos7210250-deployment-new-metrics   ClusterIP   10.96.237.242   <none>        8080/TCP   3h5m
```

### service endpoint

```bash
kubectl get ep cfos7210250-deployment-new-metrics
```
result
```
NAME                                 ENDPOINTS             AGE
cfos7210250-deployment-new-metrics   10.244.106.102:8080   3h5m
```


### pod 
the agent pod that has label "metrics-enabled=true" will run metric server 
```
kubectl get pod -o wide -l metrics-enabled=true
```
result
```
NAME                  READY   STATUS    RESTARTS   AGE    IP               NODE                             NOMINATED NODE   READINESS GATES
route-manager-v4sl6   1/1     Running   0          3h4m   10.244.106.102   ip-10-244-106-102.ec2.internal   <none>           <none>
```

### related agent log

```bash
kubectl logs  po/route-manager-v4sl6 | grep "Metrics server" 
```
result
```
2024/12/09 01:56:58 yagosys.com/cni/pkg/logger.LogSuccess: Metrics server started on port 8080
2024/12/09 01:56:58 yagosys.com/cni/pkg/configmap.HandleMetricsConfigMap: Metrics server initialized successfully
```
