DOCKERFILE := ../../../.docker/prod.Dockerfile
BUILD_CONTEXT := ../../..
ARCHIVES_DIR := build-cache/archives
ARCHIVES_STAMP := $(ARCHIVES_DIR)/.stamp

IN_DISTROBOX := $(shell if { [ -n "$$DISTROBOX_ENTER_PATH" ] || [ -n "$$DISTROBOX_HOST_HOME" ]; } \
	&& command -v distrobox-host-exec >/dev/null 2>&1; then echo yes; else echo no; fi)
HOST_EXEC := $(if $(filter yes,$(IN_DISTROBOX)),distrobox-host-exec,)
RUNTIME_PROBE := $(if $(HOST_EXEC),$(HOST_EXEC) sh -lc,sh -lc)

DOCKER_AVAILABLE := $(shell $(RUNTIME_PROBE) 'command -v docker >/dev/null 2>&1 && echo yes || true' 2>/dev/null)
PODMAN_AVAILABLE := $(shell $(RUNTIME_PROBE) 'command -v podman >/dev/null 2>&1 && echo yes || true' 2>/dev/null)

ifeq ($(DOCKER_AVAILABLE),yes)
CONTAINER_ENGINE := docker
else ifeq ($(PODMAN_AVAILABLE),yes)
CONTAINER_ENGINE := podman
endif

CONTAINER_CMD := $(strip $(HOST_EXEC) $(CONTAINER_ENGINE))

.PHONY: all clean

all: $(ARCHIVES_STAMP)

$(ARCHIVES_DIR):
	mkdir -p $@

$(ARCHIVES_STAMP): $(DOCKERFILE) | $(ARCHIVES_DIR)
	@if [ -z "$(CONTAINER_ENGINE)" ]; then \
		echo "error: neither docker nor podman was detected" >&2; \
		exit 1; \
	fi
	@set -eu; \
	image_tag="openvas-build-archives:$$PPID-$$$$"; \
	container_name="openvas-build-archives-$$PPID-$$$$"; \
	trap '$(CONTAINER_CMD) rm -f "$$container_name" >/dev/null 2>&1 || true; $(CONTAINER_CMD) rmi -f "$$image_tag" >/dev/null 2>&1 || true' EXIT; \
	rm -rf $(ARCHIVES_DIR); \
	mkdir -p $(ARCHIVES_DIR); \
	echo "Using container runtime: $(CONTAINER_CMD)"; \
	$(CONTAINER_CMD) build \
		-f $(DOCKERFILE) \
		--target build-archives \
		-t "$$image_tag" \
		$(BUILD_CONTEXT); \
	$(CONTAINER_CMD) create --name "$$container_name" "$$image_tag" >/dev/null; \
	$(CONTAINER_CMD) cp "$$container_name:/archives/." $(ARCHIVES_DIR)/; \
	$(CONTAINER_CMD) rm "$$container_name" >/dev/null; \
	$(CONTAINER_CMD) rmi "$$image_tag" >/dev/null; \
	touch $@

clean:
	rm -rf $(ARCHIVES_DIR)
