.PHONY := auth-server,docker-registry
USER :="holla"
PASSWORD :="diewaldfee"
BASE_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.DEFAULT_GOAL := start

# Parameter:
# 1: the name of the container to start
# 2: the make command to execute if container name was not found
define start_container
@if docker ps -a --format '{{.Names}}' | grep -wq $(1); then \
	echo "Starting existing container: $(1)"; \
	docker start $(1); \
else \
	echo "Container $(1) not found. Running: $(2)"; \
	$(MAKE) $(2); \
fi
endef

IMAGES_FILE := images
LOCAL_REGISTRY := localhost:5000

rm-local-images:
	@echo "Removing images pulled by mirror-images."
	@while IFS= read -r image; do \
		if [ -n "$$image" ]; then \
			echo "removing $$image"; \
			docker rmi $$image 2> /dev/null || true ; \
		fi \
	done < $(IMAGES_FILE)


mirror-images:
	@echo "Begin mirroring images to $(LOCAL_REGISTRY)."
	@while IFS= read -r image; do \
		if [ -n "$$image" ]; then \
			echo "docker pull $$image"; \
			docker pull $$image > /dev/null 2>&1; \
			repo_tag=$$(echo $$image | sed 's|.*/||'); \
			local_tag=$(LOCAL_REGISTRY)/$$image; \
			echo "docker tag $$image $$local_tag"; \
			docker tag $$image $$local_tag > /dev/null 2>&1; \
			echo "docker push $$local_tag"; \
			docker push $$local_tag > /dev/null 2>&1; \
			docker rmi $$local_tag > /dev/null 2>&1; \
		fi \
	done < $(IMAGES_FILE)
	@echo "End $(LOCAL_REGISTRY)."


certs/domain.crt:
	openssl req -newkey rsa:4096 -nodes -sha256 -keyout certs/domain.key \
	  -x509 -days 365 -out certs/domain.crt \
	  -subj "/CN=localhost"

auth-server:
	docker run -d \
		--name auth_server \
		-p 5001:5001 \
		-v "$(BASE_PATH)/config:/config" \
		-v "$(BASE_PATH)/auth:/config/auth" \
		-v "$(BASE_PATH)/certs:/certs" \
		cesanta/docker_auth

stop-auth-server:
	docker stop auth_server

start-auth-server:
	$(call start_container,auth_server,auth-server)

rm-auth-server: stop-auth-server
	docker rm auth_server

docker-registry: 
	docker run -d \
		--name registry \
		-p 5000:5000 \
		-v "$(BASE_PATH)/certs:/certs" \
		-e REGISTRY_AUTH=token \
		-e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
		-e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
		-e REGISTRY_AUTH_TOKEN_REALM=https://localhost:5001/auth \
		-e REGISTRY_AUTH_TOKEN_SERVICE=localhost:5000 \
		-e REGISTRY_AUTH_TOKEN_ISSUER=MyAuthServer \
		-e REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/certs/domain.crt \
		registry:2

stop-docker-registry:
	docker stop registry

start-docker-registry:
	$(call start_container,registry,docker-registry)

stop: stop-auth-server stop-docker-registry

start: certs/domain.crt start-auth-server start-docker-registry

start-mirror: start mirror-images

rm-docker-registry: stop-docker-registry
	docker rm registry

rm: rm-docker-registry rm-auth-server
