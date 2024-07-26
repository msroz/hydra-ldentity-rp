FROM golang:1.22.5-alpine3.19

WORKDIR /app

ENV GOOS linux
ENV GOARCH amd64
ENV PATH $PATH:/go/bin/linux_amd64
ENV CGO_ENABLED 0
RUN \
  echo http://dl-cdn.alpinelinux.org/alpine/edge/community/ >> /etc/apk/repositories && \
  apk update --no-cache && \
  apk add --virtual .build \
  bash \
  git \
  gcc \
  make \
  musl-dev \
  libffi-dev \
  curl \
  mysql-client \
  ca-certificates && \
  apk add python3 && \
  update-ca-certificates

RUN go install github.com/air-verse/air@latest
# RUN go install github.com/go-task/task/v3/cmd/task@latest
# COPY Taskfile.yml .
# RUN task setup

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . /app
