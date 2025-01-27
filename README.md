# upload-recordings

A (hopefully) more performant process for uploading jambonz call recordings written in C++

## Building

### Prerequisites

Install libraries for mp3 decoding, mysql database access, and crypto stuff.

```bash
sudo apt-get update
sudo apt install libcjson-dev libmp3lame-dev libmysqlcppconn-dev libssl-dev 
```

Install and build libwebsockets.
```
cd /usr/local/src
git clone https://github.com/warmcat/libwebsockets.git -b v4.3.3
cd libwebsockets
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo && make && sudo make install
```

 Install and build AWS C++ sdk
 ```bash
 cd /usr/local/src
 git https://github.com/aws/aws-sdk-cpp
 cd aws-sdk-cpp
 git submodule update --init --recursive
 mkdir -p build && cd build
  cmake .. -DBUILD_ONLY="s3;core;s3-crt" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=ON -DCMAKE_CXX_FLAGS="-Wno-unused-parameter -Wno-error=nonnull -Wno-error=deprecated-declarations -Wno-error=uninitialized -Wno-error=maybe-uninitialized -Wno-error=array-bounds"
make
sudo make install
```

then you can build

```
cd /usr/local/src
git clone https://github.com/jambonz/upload-recordings.git
cd upload-recordings
autoreconf -fi
mkdir build && cd $_
../configure
make
sudo make install
```

Install the upload_recordings.service file, edit the environment variables for your system, and start it.  Whatever port the process is listening on, don't forget to open the firewall for that tcp port.

