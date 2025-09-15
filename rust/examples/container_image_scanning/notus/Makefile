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

RSYNC := rsync -ltvrP --delete --exclude private/ --perms --chmod=Fugo+r,Fug+w,Dugo-s,Dugo+rx,Dug+w

RSYNC_BASE := rsync://feed.community.greenbone.net
VERSION := 24.10

notus:
	${RSYNC} ${RSYNC_BASE}/community/vulnerability-feed/${VERSION}/vt-data/notus/ notus

notus-run: notus
	docker run -d \
		--name notus \
		-e OPENVASD_MODE="service_notus" \
		-e LISTENING="0.0.0.0:80" \
		-p 6969:80 \
		-v "$(BASE_PATH)/notus:/var/lib/notus" \
		registry.community.greenbone.net/community/openvas-scanner:stable

stop-notus:
	docker stop -t 1 notus

start-notus:
	$(call start_container,notus,notus-run)

rm-notus: stop-notus
	docker rm notus

stop: stop-notus

start: start-notus

rm: rm-notus
