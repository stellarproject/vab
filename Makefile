GO_LDFLAGS=-s -w

all:
	CGO_ENABLED=0 go build -v -ldflags '${GO_LDFLAGS} -extldflags "-static"'

install:
	@install vab /usr/local/bin/vab
