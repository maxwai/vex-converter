FROM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414

RUN apk add git make

RUN git clone https://github.com/openvex/vexctl.git /vexctl

WORKDIR /vexctl

RUN git checkout ef4d4b47b1e6aa1f9f40f3cddca6c42617ddd9bf

RUN make

ENTRYPOINT ["./vexctl", "validate", "--strict"]
