FROM openresty/openresty:alpine-fat AS production-stage

RUN set -x \
    && /bin/sed -i 's,http://dl-cdn.alpinelinux.org,https://mirrors.aliyun.com,g' /etc/apk/repositories \
    && apk add --no-cache --virtual .builddeps \
    automake \
    autoconf \
    libtool \
    pkgconfig \
    cmake \
    git

COPY rockspec/apisix-2.1-0.rockspec /root/apisix-2.1-0.rockspec
RUN luarocks install /root/apisix-2.1-0.rockspec --tree=/usr/local/apisix/deps \
    && cp -v /usr/local/apisix/deps/lib/luarocks/rocks-5.1/apisix/2.1-0/bin/apisix /usr/bin/ \
    && bin='#! /usr/local/openresty/luajit/bin/luajit\npackage.path = "/usr/local/apisix/?.lua;" .. package.path' \
    && sed -i "1s@.*@$bin@" /usr/bin/apisix \
    && mv /usr/local/apisix/deps/share/lua/5.1/apisix /usr/local/apisix \
    && apk del .builddeps build-base make unzip

FROM alpine:3.11 AS last-stage

# add runtime for Apache APISIX
RUN set -x \
    && /bin/sed -i 's,http://dl-cdn.alpinelinux.org,https://mirrors.aliyun.com,g' /etc/apk/repositories \
    && apk add --no-cache bash libstdc++ curl

WORKDIR /usr/local/apisix

COPY --from=production-stage /usr/local/openresty/ /usr/local/openresty/
COPY --from=production-stage /usr/local/apisix/ /usr/local/apisix/
COPY --from=production-stage /usr/bin/apisix /usr/bin/apisix

# 自定义服务发现插件
COPY apisix/discovery/discovery.lua /usr/local/apisix/apisix/discovery/discovery.lua
COPY conf/config.yaml /usr/local/apisix/conf/config.yaml
COPY conf/apisix.yaml /usr/local/apisix/conf/apisix.yaml

ENV PATH=$PATH:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin

EXPOSE 9080 9443

CMD ["sh", "-c", "/usr/bin/apisix init && /usr/bin/apisix init_etcd && /usr/local/openresty/bin/openresty -p /usr/local/apisix -g 'daemon off;'"]

STOPSIGNAL SIGQUIT