FROM golang:1.9

MAINTAINER sinchie

ENV GOPATH /opt/gopath

RUN mkdir -p /opt/gopath/src/github.com/sinchie/bargo
COPY ./ /opt/gopath/src/github.com/sinchie/bargo
WORKDIR /opt/gopath/src/github.com/sinchie/bargo

RUN go get && go build -o bargo

CMD ["./bargo"]