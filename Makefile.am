MYVERSION=$(shell git describe --always 2>/dev/null || echo 1.0.0)

bin_PROGRAMS = upload_recordings

upload_recordings_SOURCES = main.cpp \
  protocol-lws.c \
  session.cpp \
  session-wrapper.cpp \
  storage-uploader.cpp \
  s3-compatible-uploader.cpp \
  azure-uploader.cpp \
  google-uploader.cpp \
  upload-utils.cpp \
  mysql-helper.cpp \
  s3-client-manager.cpp

# Note: No need for thread-pool.cpp and connection-manager.cpp which are header-only

upload_recordings_CPPFLAGS = $(LIBWEBSOCKETS_CFLAGS) \
  $(BOOST_CPPFLAGS) \
  -I/usr/include/lame \
  -I/usr/include/cppconn \
  -I/usr/include/aws-sdk-cpp \
  -I/usr/include/spdlog \
  -I/usr/include/curl \
  -DUPLOADER_VERSION=\"$(MYVERSION)\"

upload_recordings_LDADD = $(LIBWEBSOCKETS_LIBS) \
  $(BOOST_LDFLAGS) \
  $(BOOST_SYSTEM_LIB) \
  $(BOOST_THREAD_LIB) \
  -lmp3lame \
  -lmysqlcppconn \
  -laws-cpp-sdk-s3-crt \
  -laws-cpp-sdk-s3 \
  -laws-cpp-sdk-core \
  -laws-cpp-sdk-monitoring \
  -lspdlog \
  -lev \
  -lfmt \
  -lcurl \
  -lssl \
  -lcrypto \
  -lpthread

if TCMALLOC
upload_recordings_LDADD += -ltcmalloc
endif

AM_CXXFLAGS = -std=c++17
AM_LDFLAGS = -L/usr/lib -L/usr/local/lib