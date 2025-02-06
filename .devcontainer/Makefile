# TODO: 
# - add update script
# - change install-nvim to adapt update script to also update neovim


# Get the UID and GID of the user those will be used within the Dockerfile to share the same id between host and container.
UID := $(shell id -u)
GID := $(shell id -g)
MF_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
# if podman exists, use it instead of docker 
ifneq (,$(shell which podman))
	CONTAINERR=podman
else
	CONTAINERR=docker
endif
# disable docker hints, who needs that?
export DOCKER_CLI_HINTS=false

.PHONY: build

command-exists = $(CONTAINERR) exec -it openvas-dev command -v $(1) >/dev/null 2>&1 && echo "exists" || echo "not exists"
# @if [ "$$(basename $$SHELL)" = "fish" ]; then \
get-shell = $(basename $(notdir $(SHELL)))

build:
	$(CONTAINERR) build \
		--build-arg UID=$(UID) \
		--build-arg GID=$(GID) \
		-t openvas-dev:latest \
		.

start: 
	$(CONTAINERR) start openvas-dev

create:
	$(CONTAINERR) create -it \
		--name openvas-dev \
		-v $(HOME)/.ssh:/home/user/.ssh\
		-v $(HOME)/.config:/home/user/.config\
		-v $(HOME)/.gitconfig:/home/user/.gitconfig \
		openvas-dev:latest

is-running:
	$(CONTAINERR) ps -q --filter "name=openvas-dev" | grep -q . 

enforce-running:
	$(MAKE) is-running || $(MAKE) start || $(MAKE) create && $(MAKE) start 

install-fish: enforce-running
	$(CONTAINERR) exec -it openvas-dev /bin/bash -c "sudo apt update"
	$(CONTAINERR) exec -it openvas-dev /bin/bash -c "sudo apt install -y fish"
	# doesn't work because of attached tty on create there is no reinit of the shell
	#$(CONTAINERR) exec -it openvas-dev /bin/bash -c "sudo chsh -s /usr/bin/fish user"

install-pyright: enforce-running
	$(CONTAINERR) exec -it openvas-dev /bin/bash -c "pipx install pyright"


install-rg-fzf: enforce-running
	$(CONTAINERR) exec -it openvas-dev /bin/bash -c "sudo apt update"
	$(CONTAINERR) exec -it openvas-dev /bin/bash -c "sudo apt install -y ripgrep fzf"

install-nvim: install-rg-fzf
	$(CONTAINERR) exec -it openvas-dev /bin/bash -c "sudo apt install -y ninja-build gettext cmake unzip curl build-essential nodejs"
	$(CONTAINERR) exec -it openvas-dev /bin/bash -c "github-clone neovim/neovim"
	$(CONTAINERR) exec -it openvas-dev /bin/bash -c "cd /workspaces/neovim/neovim && make CMAKE_BUILD_TYPE=RelWithDebInfo && sudo make install"


enter: enforce-running
	@if $(call command-exists,fish); then \
		$(MAKE) enter-fish; \
	else \
		$(MAKE) enter-bash; \
	fi
	
enter-bash: enforce-running
	$(CONTAINERR) exec -it openvas-dev /bin/bash

# TODO: detect running shell and use that
enter-fish: enforce-running
	$(CONTAINERR) exec -it openvas-dev /usr/bin/fish

stop:
	-$(CONTAINERR) stop openvas-dev

rm: stop
	$(CONTAINERR) rm openvas-dev
