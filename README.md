# upload-recordings

A (hopefully) more performant process for uploading jambonz call recordings written in C++

## Building

### Prerequisites

```bash
 sudo apt install libcjson-dev libmp3lame-dev libmysqlcppconn-dev libssl-dev
```
 install and build AWS C++ sdk

 ```bash
 autoreconf -fi
mkdir build && cd $_
../configure
make
sudo make install
```