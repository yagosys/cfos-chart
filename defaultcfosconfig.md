### the helm deploed a default config via configmap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: defaultconfigmap
  namespace: default
  labels:
    app: fos
    category: config
data:
  config: |
    config system global
      set admin-port 8080
    end
    config system api-user
      edit "agent"
     next
    end
    config log custom-field
        edit "pod-label"
            set name "label"
            set value "protectedby=cfos"
        next
        edit "nodeip"
            set name "nodeip"
            set value "10.244.100.236"
        next
        edit "nodename"
            set name "nodename"
            set value "ip-10-244-100-236.ec2.internal"
        next
        edit "firewalllabel"
            set name "firewalllabel"
            set value "app=firewall"
        next
    end

    config firewall address
        edit "protectedpodtest"
            set subnet 192.168.200.0/24
            set type ipmask
            set comment ""
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
               edit 300
                   set utm-status enable
                   set name policy-name
                   set srcintf "vxlan0"
                   set dstintf "eth0"
                   set srcaddr "protectedpodtest"
                   set dstaddr  all 
                   set service "ALL"
                   set ssl-ssh-profile "mytest"
                   set av-profile "default"
                   set webfilter-profile "default"
                   set ips-sensor "default"
                   set av-profile "default"
                   set nat enable
                   set custom-log-fields "pod-label" "nodeip" "nodename" "firewalllabel"
                   set logtraffic all
               next
           end
  type: partial
```

### from cfos

above configmap shall be fetched by cfos and configured accordingly

```bash
cFOS # show firewall address protectedpodtest
```
result
```
config firewall address
    edit "protectedpodtest"
        set subnet 192.168.200.0 255.255.255.0
    next
end
```

```bash
cFOS # show log custom-field
```
result
```
config log custom-field
    edit "pod-label"
        set name "label"
        set value "protectedby=cfos"
    next
    edit "nodeip"
        set name "nodeip"
        set value "10.244.100.236"
    next
    edit "nodename"
        set name "nodename"
        set value "ip-10-244-100-236.ec2.internal"
    next
    edit "firewalllabel"
        set name "firewalllabel"
        set value "app=firewall"
    next
end
```

```bash

cFOS # show firewall policy

```
result
```
config firewall policy
    edit 300
        set utm-status enable
        set name "policy-name"
        set srcintf "vxlan0"
        set dstintf "eth0"
        set srcaddr "protectedpodtest"
        set dstaddr "all"
        set service "ALL"
        set ssl-ssh-profile "mytest"
        set av-profile "default"
        set webfilter-profile "default"
        set ips-sensor "default"
        set nat enable
        set custom-log-fields "pod-label" "nodeip" "nodename" "firewalllabel"
        set logtraffic all
    next
end
cFOS #
```
