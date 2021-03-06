FROM golang:1.12-alpine as builder

ARG CI_TAG
ARG BUILD_NUMBER
ARG BUILD_COMMIT_SHORT
ARG CI_BUILD_CREATED
ENV GO111MODULE on
ENV CGO_ENABLED 0
WORKDIR /src

COPY . .

RUN go build -o release/goforward \
   -mod vendor -ldflags "-w -s \
   -X main.Version=${CI_TAG} \
   -X main.BuildNumber=${BUILD_NUMBER} \
   -X main.Commit=${BUILD_COMMIT_SHORT} \
   -X main.BuildTime=${CI_BUILD_CREATED}"

FROM alpine:3.9
LABEL maintainer="codestation <codestation404@gmail.com>"

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /src/release/goforward /bin/goforward

ENTRYPOINT ["/bin/goforward"]
