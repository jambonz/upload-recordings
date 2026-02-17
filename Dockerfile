FROM debian:bookworm-slim

ARG BUILD_CPUS=4

RUN apt-get update \
  && apt-get -y --quiet --force-yes upgrade \
  && apt-get install -y --no-install-recommends ca-certificates gcc g++ make build-essential \
  cmake git autoconf automake pkg-config curl \
  libcjson-dev libmp3lame-dev libmysqlcppconn-dev libspdlog-dev libfmt-dev \
  libssl-dev libcurl4-openssl-dev libgoogle-perftools-dev libboost-all-dev \
  libev-dev

# Build libwebsockets v4.3.3 with libev support
COPY ops-ws.c.patch /tmp/ops-ws.c.patch
RUN cd /usr/local/src \
  && git clone https://github.com/warmcat/libwebsockets.git -b v4.3.3 --depth 1 \
  && cd libwebsockets/lib/roles/ws \
  && patch ops-ws.c < /tmp/ops-ws.c.patch \
  && cd /usr/local/src/libwebsockets \
  && mkdir -p build && cd build \
  && cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLWS_WITH_NETLINK=OFF -DLWS_WITH_LIBEV=1 \
  && make -j${BUILD_CPUS} \
  && make install \
  && rm -rf /usr/local/src/libwebsockets

# Build AWS SDK C++ v1.11.500
RUN cd /usr/local/src \
  && git clone https://github.com/aws/aws-sdk-cpp -b 1.11.500 --depth 1 \
  && cd aws-sdk-cpp \
  && git submodule update --init --recursive \
  && mkdir -p build && cd build \
  && cmake .. -DBUILD_ONLY="s3;core;s3-crt;monitoring" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_SHARED_LIBS=ON \
    -DENABLE_TESTING=OFF \
    -DAUTORUN_UNIT_TESTS=OFF \
    -DCMAKE_CXX_FLAGS="-Wno-unused-parameter -Wno-error=nonnull -Wno-error=deprecated-declarations -Wno-error=uninitialized -Wno-error=maybe-uninitialized -Wno-error=array-bounds" \
  && make -j${BUILD_CPUS} \
  && make install \
  && find /usr/local/src/aws-sdk-cpp/ -type f -name "*.pc" -exec cp -t /usr/local/lib/pkgconfig/ {} + \
  && rm -rf /usr/local/src/aws-sdk-cpp

COPY . /usr/local/src/upload-recordings

RUN cd /usr/local/src/upload-recordings \
  && export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH \
  && autoreconf -fi \
  && mkdir -p build && cd build \
  && ../configure --enable-tcmalloc=yes CXXFLAGS='-g -O2' \
  && make -j${BUILD_CPUS} \
  && make install \
  && apt-get purge -y --quiet --auto-remove gcc g++ make cmake build-essential git autoconf automake pkg-config \
  && rm -rf /var/lib/apt/* \
  && rm -rf /var/lib/dpkg/* \
  && rm -rf /var/lib/cache/* \
  && rm -Rf /var/log/* \
  && rm -Rf /var/lib/apt/lists/* \
  && rm -Rf /usr/local/src/upload-recordings

RUN ldconfig

RUN mkdir -p /tmp/uploads

EXPOSE 3000

ENTRYPOINT ["upload_recordings"]
CMD ["--port", "3000"]
