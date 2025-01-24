#!/bin/bash -e

# Ensure an input file is specified
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <input_file>"
    exit 1
fi

input_file="$1"

# Check if the file exists
if [ ! -f "$input_file" ]; then
    echo "Error: File does not exist - $input_file"
    exit 1
fi

# Read the file and prepend six spaces to each line
license_data=$(sed 's/^/      /' $input_file)

# Create the ConfigMap YAML file with modified license data
cat <<EOF >cfos_license.yaml
apiVersion: v1
kind: ConfigMap
metadata:
    name: fos-license
    labels:
        app: fos
        category: license
data:
    license: |+
$license_data
EOF

echo "cfos_license.yaml created."

