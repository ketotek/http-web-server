
all:
	make -C src/

run: src/server
	@sudo src/server

.PHONY:
clean:
	make -C src/ clean
