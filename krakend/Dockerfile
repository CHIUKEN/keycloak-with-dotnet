FROM devopsfaith/krakend:2.6.3 AS builder

COPY krakend.json /tmp/krakend.json

# The linting needs the final krakend.json file
RUN krakend check -c /tmp/krakend.json --lint

FROM devopsfaith/krakend:2.6.3
COPY --from=builder --chown=krakend:nogroup /tmp/krakend.json .