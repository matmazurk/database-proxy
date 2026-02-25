FROM golang:1.23-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /database-proxy .

FROM alpine:3.19
COPY --from=build /database-proxy /database-proxy
ENTRYPOINT ["/database-proxy"]
