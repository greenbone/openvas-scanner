# Get the UID and GID of the user those will be used within the Dockerfile to share the same id between host and container.
UID := $(shell id -u)
GID := $(shell id -g)

.PHONY: build

build:
	docker build \
		--build-arg UID=$(UID) \
		--build-arg GID=$(GID) \
		-t openvas-dev:latest \
		.

run-tmp:
	docker run -it --rm \
		-v $(HOME)/.ssh:/home/user/.ssh\
		-v $(HOME)/.config:/home/user/.config\
		-v $(HOME)/src:/home/user/src \
		openvas-dev:latest
