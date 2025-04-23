[[ $defaultClustername == "" ]] && defaultClustername="my-first-cluster-1"
gkeClusterName=$defaultClustername
clustersearchstring=$(gcloud container clusters list --filter=name=$gkeClusterName --format="value(name)" --limit=1)
#projectName=$(gcloud config list --format="value(core.project)")
#zone=$(gcloud config list --format="value(compute.zone)" --limit=1)
filename="02_modifygkevmipforwarding.sh.gen.sh"

cat << EOF > $filename
projectName=\$(gcloud config list --format="value(core.project)")
zone=\$(gcloud config list --format="value(compute.zone)" --limit=1)
node_list=\$(gcloud compute instances list --filter="name~'$clustersearchstring'"  --format="value(name)" )
for name in \$node_list; do {

gcloud compute instances export \$name \
    --project \$projectName \
    --zone \$zone \
    --destination=./\$name.txt
grep -q "canIpForward: true" \$name.txt || sed -i '/networkInterfaces/i canIpForward: true' \$name.txt
sed '/networkInterfaces/i canIpForward: true' \$name.txt 
gcloud compute instances update-from-file \$name\
    --project \$projectName \
    --zone \$zone \
    --source=\$name.txt \
    --most-disruptive-allowed-action=REFRESH
echo "done for \$name"
}
done
EOF
chmod +x $filename
./$filename
