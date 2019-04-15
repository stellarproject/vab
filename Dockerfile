FROM golang:1.12 as builder

ADD . /go/src/github.com/stellarproject/vab
WORKDIR /go/src/github.com/stellarproject/vab

RUN make

FROM scratch

COPY --from=builder /go/src/github.com/stellarproject/vab/vab /usr/local/bin/
