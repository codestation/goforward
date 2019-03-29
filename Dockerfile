FROM golang:1.12-alpine as builder

ARG BUILD_NUMBER
ARG BUILD_COMMIT_SHORT
ENV GO111MODULE on
ENV CGO_ENABLED 0

WORKDIR /app
COPY . .

RUN go install -mod vendor -ldflags "-w -s \
   -X main.BuildNumber=${BUILD_NUMBER} \
   -X main.BuildCommit=${BUILD_COMMIT_SHORT} \
  -X \"main.BuildTime=$(date -u '+%Y-%m-%d %I:%M:%S %Z')\"" \
  -a .

FROM alpine:3.9
LABEL maintainer="codestation <codestation404@gmail.com>"

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /go/bin/goforward /usr/local/bin/goforward

ENTRYPOINT ["/usr/local/bin/goforward"]
