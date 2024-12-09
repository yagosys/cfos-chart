### deploy protected application
```bash
kubectl apply -f diag.yaml
```

result
```bash
kubectl get pod -l protectedby=cfos
```

result
```bash
NAME                   READY   STATUS    RESTARTS   AGE
diag-f86f84b9c-f8kqs   1/1     Running   0          3h56m
```

### scale protected application from 1 node to 27 pods


```bash
 k deployment diag --replicas=27
```
result
deployment.apps/diag scaled
```
```bash
k rollout status deployment diag
```
result
```bash
deployment "diag" successfully rolled out
```

generate test traffic 

```bash
while true; do cat nc_test.sh | kubectl exec -i po/route-manager-fq7l6 -- sh ; sleep 2; done
```

after a while, stop it, then check keda result


```bash
kubectl get hpa
```
you are expected to see more cfos is up and running 

result
```
NAME                                         REFERENCE                               TARGETS                                       MINPODS   MAXPODS   REPLICAS   AGE
keda-hpa-cfos7210250-deployment-new-scaler   Deployment/cfos7210250-deployment-new   3/50 (avg), 68517888/400M (avg) + 1 more...   1         5         3          3h53m
```

more detail about events
```bash
kubectl describe hpa
```
result
```bash
Name:                                            keda-hpa-cfos7210250-deployment-new-scaler
Namespace:                                       default
Labels:                                          app.kubernetes.io/instance=cfos7210250-deployment-new
                                                 app.kubernetes.io/managed-by=Helm
                                                 app.kubernetes.io/name=cfos
                                                 app.kubernetes.io/part-of=cfos7210250-deployment-new-scaler
                                                 app.kubernetes.io/version=7.2.1.255
                                                 helm.sh/chart=cfos-0.1.20
                                                 scaledobject.keda.sh/name=cfos7210250-deployment-new-scaler
Annotations:                                     meta.helm.sh/release-name: cfos7210250-deployment-new
                                                 meta.helm.sh/release-namespace: default
CreationTimestamp:                               Mon, 09 Dec 2024 09:56:44 +0800
Reference:                                       Deployment/cfos7210250-deployment-new
Metrics:                                         ( current / target )
  "s0-metric-api-value" (target average value):  3 / 50
  "s1-metric-api-value" (target average value):  68517888 / 400M
  "s2-metric-api-value" (target average value):  38334m / 100
Min replicas:                                    1
Max replicas:                                    5
Deployment pods:                                 3 current / 3 desired
Conditions:
  Type            Status  Reason               Message
  ----            ------  ------               -------
  AbleToScale     True    ScaleDownStabilized  recent recommendations were higher than current one, applying the highest recent recommendation
  ScalingActive   True    ValidMetricFound     the HPA was able to successfully calculate a replica count from external metric s2-metric-api-value(&LabelSelector{MatchLabels:map[string]string{scaledobject.keda.sh/name: cfos7210250-deployment-new-scaler,},MatchExpressions:[]LabelSelectorRequirement{},})
  ScalingLimited  False   DesiredWithinRange   the desired count is within the acceptable range
Events:
  Type     Reason                        Age                    From                       Message
  ----     ------                        ----                   ----                       -------
  Warning  FailedGetExternalMetric       46m (x18 over 3h52m)   horizontal-pod-autoscaler  unable to get external metric default/s2-metric-api-value/&LabelSelector{MatchLabels:map[string]string{scaledobject.keda.sh/name: cfos7210250-deployment-new-scaler,},MatchExpressions:[]LabelSelectorRequirement{},}: unable to fetch metrics from external metrics API: rpc error: code = Unknown desc = error when getting metric values metric:s2-metric-api-value encountered error
  Warning  FailedComputeMetricsReplicas  46m (x18 over 3h52m)   horizontal-pod-autoscaler  invalid metrics (3 invalid out of 3), first error is: failed to get s0-metric-api-value external metric value: failed to get s0-metric-api-value external metric: unable to get external metric default/s0-metric-api-value/&LabelSelector{MatchLabels:map[string]string{scaledobject.keda.sh/name: cfos7210250-deployment-new-scaler,},MatchExpressions:[]LabelSelectorRequirement{},}: unable to fetch metrics from external metrics API: rpc error: code = Unknown desc = error when getting metric values metric:s0-metric-api-value encountered error
  Warning  FailedGetExternalMetric       45m (x19 over 3h52m)   horizontal-pod-autoscaler  unable to get external metric default/s0-metric-api-value/&LabelSelector{MatchLabels:map[string]string{scaledobject.keda.sh/name: cfos7210250-deployment-new-scaler,},MatchExpressions:[]LabelSelectorRequirement{},}: unable to fetch metrics from external metrics API: rpc error: code = Unknown desc = error when getting metric values metric:s0-metric-api-value encountered error
  Warning  FailedGetExternalMetric       45m (x19 over 3h52m)   horizontal-pod-autoscaler  unable to get external metric default/s1-metric-api-value/&LabelSelector{MatchLabels:map[string]string{scaledobject.keda.sh/name: cfos7210250-deployment-new-scaler,},MatchExpressions:[]LabelSelectorRequirement{},}: unable to fetch metrics from external metrics API: rpc error: code = Unknown desc = error when getting metric values metric:s1-metric-api-value encountered error
  Normal   SuccessfulRescale             10m                    horizontal-pod-autoscaler  New size: 2; reason: external metric s2-metric-api-value(&LabelSelector{MatchLabels:map[string]string{scaledobject.keda.sh/name: cfos7210250-deployment-new-scaler,},MatchExpressions:[]LabelSelectorRequirement{},}) above target
  Normal   SuccessfulRescale             3m33s (x2 over 3h46m)  horizontal-pod-autoscaler  New size: 1; reason: All metrics below target
  Normal   SuccessfulRescale             2m18s (x2 over 9m18s)  horizontal-pod-autoscaler  New size: 3; reason: external metric s2-metric-api-value(&LabelSelector{MatchLabels:map[string]string{scaledobject.keda.sh/name: cfos7210250-deployment-new-scaler,},MatchExpressions:[]LabelSelectorRequirement{},}) above target
➜  examples git:(main
```

