ARG VERSION

FROM alpine:3.10

LABEL "maintainer"="dev@anchore.com"
LABEL "version"=$VERSION

RUN apk update && apk add --no-cache git bash ca-certificates && update-ca-certificates

COPY bin/anchore-adapter /app/anchore-adapter

ENTRYPOINT ["/app/anchore-adapter"]
