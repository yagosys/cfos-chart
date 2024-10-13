## Install cfos-chart
helm repo add cfos-chart https://yagosys.github.io/cfos-chart
helm repo update
helm search repo cfos-chart

## Install deployment 

helm upgrade --install cfos7210250-deployment-new cfos-chart/cfos


