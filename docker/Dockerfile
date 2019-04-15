FROM golang

COPY src ${GOPATH}/src

WORKDIR ${GOPATH}/src

RUN go get golang.org/x/net/ipv4 
RUN go honnef.co/go/netdb
 
