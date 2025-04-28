#!/bin/bash

# Get all node names
node_names=$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}')

# Loop through each node name
for node in $node_names; do
  echo "Labeling node: $node"

  # Assign label app=true
  kubectl label nodes "$node" app=true --overwrite

  # Assign label security=true
  kubectl label nodes "$node" security=true --overwrite

  echo "Node $node labeled successfully."
done

echo "All nodes have been labeled with app=true and security=true."
