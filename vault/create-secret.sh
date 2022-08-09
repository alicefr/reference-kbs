#!/bin/bash

docker exec -ti vault vault kv put -mount=secret fakeid secret=test
docker exec -ti vault vault kv get -mount=secret fakeid

docker exec -ti vault sh -c 'tee readonly.hcl <<EOF
 path "secret/data/fakeid" {
   capabilities = ["read"]
 }
EOF
'
docker exec -ti vault vault policy write kbs readonly.hcl

VAULT_TOKEN=$(docker exec -ti vault vault token create -policy="kbs" -field=token)
echo $VAULT_TOKEN
