ARG BUILDER=higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/wasm-go-builder:go1.24.1-oras1.0.0
FROM $BUILDER as builder


ARG GOPROXY
ENV GOPROXY=${GOPROXY}

ARG EXTRA_TAGS=""
ENV EXTRA_TAGS=${EXTRA_TAGS}

ARG PLUGIN_NAME=hello-world

WORKDIR /workspace

COPY . .

WORKDIR /workspace/extensions/$PLUGIN_NAME

RUN go mod tidy
RUN go mod tidy
RUN export GOOS=wasip1; \
    export GOARCH=wasm; \
    go build -buildmode=c-shared \
        $(if [ -n "${EXTRA_TAGS}" ]; then echo "-tags=\"${EXTRA_TAGS}\""; fi) \
        -o /main.wasm

FROM scratch as output

COPY --from=builder /main.wasm plugin.wasm
