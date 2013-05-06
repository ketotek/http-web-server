
all: setbindcap

build:
	make -C src/

setbindcap: build
	@echo "Set capabilty for port binding. Might require your password"
	sudo setcap cap_net_bind_service=+ep src/server

run: src/server
	src/server

.PHONY:
clean:
	make -C src/ clean
