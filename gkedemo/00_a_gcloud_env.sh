#/bin/bash -xe
filename="00_a_gcloud_env.sh.gen.sh"
cat << EOF > $filename
project=\$(gcloud config list --format="value(core.project)")
[[ -z \$region ]] && region="us-central1"
[[ -z \$zone ]] && zone="us-central1-a"
export region=\$region
export zone=\$zone
gcloud config set project \$project
gcloud config set compute/region \$region
gcloud config set compute/zone \$zone
gcloud config list
EOF
chmod +x $filename

./$filename
