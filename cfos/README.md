:1

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
helm show all cfos-chart/cfos
```

