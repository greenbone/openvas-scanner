.PHONY: remove
ALL: generate
	
server.rsa:
	sh server_certificates.sh
client.rsa:
	sh client_certificates.sh

generate: server.rsa client.rsa

remove:
	rm server.rsa server.pem
	rm client.rsa client.pem
