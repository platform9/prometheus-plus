FROM golang:1.17 as builder

WORKDIR /workspace

# Copy go modules
COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

# Copy the go source

COPY cmd/main.go cmd/main.go
COPY pkg/ pkg/
COPY promplus/ promplus/

RUN mkdir -p build/bin

RUN GOOS=linux GOARCH=amd64 go build -o build/bin/promplus cmd/main.go


FROM alpine:3.16 

COPY --from=builder /workspace/build/bin/promplus /bin/

COPY promplus /etc/promplus/

RUN chmod +x /bin/promplus

ENTRYPOINT [ "/bin/promplus" ]
