all: openvasd-server.key client-certs/client1.pem

openvasd-server.key:
	cd ../rust/examples/tls/self-signed/ && make
	mv ../rust/examples/tls/self-signed/server.pem openvasd-server.pem
	mv ../rust/examples/tls/self-signed/server.rsa openvasd-server.key

client-certs/client1.pem:
	mkdir -p client-certs
	mkdir -p client-keys
	cd ../rust/examples/tls/self-signed/ && make
	mv ../rust/examples/tls/self-signed/server.pem client-certs/client1.pem
	mv ../rust/examples/tls/self-signed/server.rsa client-keys/client1.key

