#!/bin/bash

set -x

docker run \
	-td \
	-u 0 \
	--security-opt label=disable \
	--cap-add=IPC_LOCK \
	--name vault \
	--hostname vault \
	--network host \
	-p 8200 \
	-v vault:/vault/data \
	-e 'VAULT_ADDR=http://127.0.0.1:8200' \
	-e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' \
	-e 'VAULT_SKIP_VERIFY=true' \
	-e 'VAULT_TOKEN=myroot' \
	-e 'VAULT_LOG_LEVEL=debug' \
	vault server -dev
