## service for access cFOS API

```bash
kubectl get svc cfos-api-service
```
result
```
NAME               TYPE       CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
cfos-api-service   NodePort   10.96.222.222   <none>        8080:31943/TCP   170m
```

the endpoint is cfos POD

```bash
kubectl get ep cfos-api-service
NAME               ENDPOINTS             AGE
cfos-api-service   10.244.118.193:8080   172m
```


from agent pod, you can verify whether the endpoint is reachable

```bash
kubeclt exec -it po/route-manager-fq7l6 -- curl 10.96.222.222:8080
```
expect result
```
welcome to the REST API server%
```

you can also access the api through nodeport service from kubenenetes node ip

```bash
k get node -o wide
```
result
```
NAME                             STATUS   ROLES    AGE     VERSION               INTERNAL-IP      EXTERNAL-IP   OS-IMAGE                       KERNEL-VERSION                    CONTAINER-RUNTIME
ip-10-244-100-236.ec2.internal   Ready    <none>   4h44m   v1.30.6-eks-94953ac   10.244.100.236   <none>        Amazon Linux 2023.6.20241111   6.1.115-126.197.amzn2023.x86_64   containerd://1.7.23
ip-10-244-106-102.ec2.internal   Ready    <none>   4h44m   v1.30.6-eks-94953ac   10.244.106.102   <none>        Amazon Linux 2023.6.20241111   6.1.115-126.197.amzn2023.x86_64   containerd://1.7.23
```
then 
```
k exec -it po/route-manager-fq7l6 -- curl http://10.244.100.236:31943
```
result
```
welcome to the REST API server%
```
or
```
k exec -it po/route-manager-fq7l6 -- curl http://10.244.106.102:31943
```
result
```
welcome to the REST API server%
```

the cfos configured with api user via configmap with name "defaultconfigmap". 
the defaultconfigmap is part of helm default deployment 

```bash
config system global
  set admin-port 8080
end
config system api-user
  edit "agent"
 next
end
```
