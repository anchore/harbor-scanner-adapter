FROM alpine:3.10

ARG COMMIT

LABEL "maintainer"="dev@anchore.com"
LABEL "commit"=${COMMIT}
LABEL "source"="https://github.com/anchore/harbor-scanner-adapter"

RUN apk update && apk add --no-cache curl bash ca-certificates && update-ca-certificates

COPY anchore-adapter /app/anchore-adapter

ENTRYPOINT ["/app/anchore-adapter"]
