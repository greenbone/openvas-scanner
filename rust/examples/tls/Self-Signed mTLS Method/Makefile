.PHONY: client server namespace delete deploy

server:
	# only when server.rsa is not available
	[ ! -f server.rsa ] && sh server_certificates.sh || true
client:
	# only when client.rsa is not available
	[ ! -f client.rsa ] && sh client_certificates.sh || true

namespace:
	kubectl create namespace openvasd || true

delete: 
	kubectl delete secret ingress-certificate --namespace openvasd || true
	kubectl delete secret client-certs --namespace openvasd || true



deploy: namespace server client
	kubectl create secret generic ingress-certificate \
		--from-file=key.pem=./server.rsa \
		--from-file=certs.pem=./server.pem \
		--namespace openvasd
	kubectl create secret generic client-certs \
		--from-file=client1.pem=./client.pem \
		--namespace openvasd

