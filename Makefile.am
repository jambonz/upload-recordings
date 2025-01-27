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
  mysql-helper.cpp 

upload_recordings_CPPFLAGS = $(LIBWEBSOCKETS_CFLAGS) \
  -I/usr/include/lame \
  -I/usr/include/cppconn \
  -I/usr/include/aws-sdk-cpp \
  -I/usr/include/spdlog \
  -I/usr/include/curl

upload_recordings_LDADD = $(LIBWEBSOCKETS_LIBS) \
  -lmp3lame \
  -lmysqlcppconn \
  -laws-cpp-sdk-s3-crt \
  -laws-cpp-sdk-s3 \
  -laws-cpp-sdk-core \
  -lspdlog \
  -lfmt \
  -lcurl \
  -lssl \
  -lcrypto

AM_CXXFLAGS = -std=c++17
AM_LDFLAGS = -L/usr/lib -L/usr/local/lib