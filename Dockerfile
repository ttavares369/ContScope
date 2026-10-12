FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go logs.go labels.go diagnostics.go findings.go guidance.go support.go ssh_onboarding.go telegram.go server_tags.go ./
COPY assets/ ./assets/
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${VCS_REF} -X main.buildDate=${BUILD_DATE}" -o /contscope .
FROM alpine:3.21
RUN apk add --no-cache openssh-client sshpass ca-certificates && addgroup -S contscope && adduser -S -u 1000 -G contscope contscope
COPY --from=build /contscope /usr/local/bin/contscope
RUN mkdir -p /data /home/contscope/.ssh && chown -R contscope:contscope /data /home/contscope
USER contscope
ENV CONTSCOPE_ADDR=:8080 CONTSCOPE_DATA=/data/servers.json
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/contscope"]
