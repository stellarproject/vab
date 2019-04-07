GO_LDFLAGS=-s -w

all:
	CGO_ENABLED=0 go build -v -ldflags '${GO_LDFLAGS} -extldflags "-static"'

image:
	vab build -p --ref docker.io/stellarproject/vab:latest

install:
	@install vab /usr/local/bin/vab
