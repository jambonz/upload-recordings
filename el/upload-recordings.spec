Name: upload-recordings
Version: 1.0.0
Release: 1%{?dist}
Summary: High-performance call recording uploader for jambonz
URL: https://jambonz.org
Group: System Environment/Daemons
License: MIT
Source: %{name}-%{version}.tar.gz

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: cmake
BuildRequires: rpm-build
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: git
BuildRequires: pkg-config
BuildRequires: openssl-devel
BuildRequires: zlib-devel
BuildRequires: boost-devel
BuildRequires: libcurl-devel
BuildRequires: gperftools-devel
BuildRequires: libev-devel
BuildRequires: cjson-devel
BuildRequires: lame-devel
BuildRequires: spdlog-devel
BuildRequires: fmt-devel

# Note: Requires mysql-connectors-community repo to be enabled
# Run: dnf config-manager --enable mysql-connectors-community
BuildRequires: mysql-connector-c++-devel

Requires: openssl
Requires: boost-system
Requires: boost-thread
Requires: libcurl
Requires: gperftools-libs
Requires: libev
Requires: lame-libs
Requires: cjson
Requires: spdlog
Requires: fmt

%description
A C++ service that receives call recordings over WebSocket and uploads
them to cloud storage backends including AWS S3, S3-compatible services,
Azure Blob Storage, and Google Cloud Storage.

%prep
%setup -q -n %{name}

%define binname upload_recordings

%build
# Build libwebsockets v4.3.3 from source with libev support
cd /usr/local/src
git clone https://github.com/warmcat/libwebsockets.git -b v4.3.3 --depth 1
cd libwebsockets/lib/roles/ws
patch ops-ws.c < %{_builddir}/%{name}/ops-ws.c.patch
cd /usr/local/src/libwebsockets
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLWS_WITH_NETLINK=OFF -DLWS_WITH_LIBEV=1
%__make
%__make install
cd %{_builddir}/%{name}

# Build AWS SDK C++ v1.11.500 from source
cd /usr/local/src
git clone https://github.com/aws/aws-sdk-cpp -b 1.11.500 --depth 1
cd aws-sdk-cpp
git submodule update --init --recursive
mkdir -p build && cd build
cmake .. -DBUILD_ONLY="s3;core;s3-crt;monitoring" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_SHARED_LIBS=ON \
    -DENABLE_TESTING=OFF \
    -DAUTORUN_UNIT_TESTS=OFF \
    -DCMAKE_CXX_FLAGS="-Wno-unused-parameter -Wno-error=nonnull -Wno-error=deprecated-declarations -Wno-error=uninitialized -Wno-error=maybe-uninitialized -Wno-error=array-bounds"
%__make
%__make install
find /usr/local/src/aws-sdk-cpp/ -type f -name "*.pc" -exec cp -t /usr/local/lib/pkgconfig/ {} +
ldconfig
cd %{_builddir}/%{name}

# Build upload-recordings
autoreconf -fi
[ -d build ] && rm -rf build
mkdir build
cd build
PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH \
    ../configure CPPFLAGS='-DNDEBUG' --enable-tcmalloc=yes CXXFLAGS='-g -O2'
%__make

%pre
getent group %{name} >/dev/null || /usr/sbin/groupadd -r %{name}
getent passwd %{name} >/dev/null || /usr/sbin/useradd -r -g %{name} \
	-s /sbin/nologin -c "%{name} daemon" -d %{_sharedstatedir}/%{name} %{name}

%install
install -D -p -m755 build/%{binname} %{buildroot}%{_bindir}/%{binname}
install -d -p -m755 %{buildroot}/tmp/uploads

# Install example systemd service file
install -D -p -m644 upload_recordings.service \
	%{buildroot}%{_docdir}/%{name}/examples/upload_recordings.service

%post
ldconfig
mkdir -p /tmp/uploads
echo ""
echo "upload-recordings has been installed. To configure systemd:"
echo "  1. Copy the example service file to /etc/systemd/system/upload_recordings.service"
echo "     Example file is in %{_docdir}/%{name}/examples/"
echo "  2. Customize the service file for your environment (MySQL, auth, encryption settings)"
echo "  3. Run: systemctl daemon-reload"
echo "  4. Run: systemctl enable upload_recordings"
echo ""

%clean
rm -rf %{buildroot}
rm -rf /usr/local/src/libwebsockets
rm -rf /usr/local/src/aws-sdk-cpp

%files
%defattr(-,root,root)
%{_bindir}/%{binname}
%dir /tmp/uploads
%{_docdir}/%{name}/examples/upload_recordings.service
%doc README.md

%changelog
* Thu Mar 26 2026 Dave Horton <daveh@beachdognet.com> - 1.0.0-1
  - Initial RPM packaging for RHEL 9
  - Builds libwebsockets and AWS SDK C++ from source
