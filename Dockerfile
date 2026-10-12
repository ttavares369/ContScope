FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go logs.go labels.go diagnostics.go findings.go guidance.go support.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /contscope .
FROM alpine:3.21
RUN apk add --no-cache openssh-client ca-certificates && addgroup -S contscope && adduser -S -u 1000 -G contscope contscope
COPY --from=build /contscope /usr/local/bin/contscope
RUN mkdir -p /data /home/contscope/.ssh && chown -R contscope:contscope /data /home/contscope
USER contscope
ENV CONTSCOPE_ADDR=:8080 CONTSCOPE_DATA=/data/servers.json
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/contscope"]
