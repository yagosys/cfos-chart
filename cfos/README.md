## install chart

```bash
helm repo add cfos-chart https://yagosys.github.io/cfos-chart
helm repo update
helm search repo cfos-chart
```

##  deploy cfos and agent

```bash
helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos
```

## check detail of chart

```
helm show all cfos-chart/cfos
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
