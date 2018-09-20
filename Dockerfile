FROM golang:1.10.3-alpine3.8 as builder

RUN apk add --no-cache git alpine-sdk make

ADD . /go/src/github.com/stellarproject/vab
WORKDIR /go/src/github.com/stellarproject/vab

RUN make

FROM scratch

COPY --from=builder /go/src/github.com/stellarproject/vab/vab /bin/vab
