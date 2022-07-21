.PHONY: build run clean all

build:
	go build -o run cmd/main.go

run: build
	./run

clean:
	rm run

all: build run clean

