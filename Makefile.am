# Define the executable name
bin_PROGRAMS = upload_recordings

# Source files for the executable
upload_recordings_SOURCES = main.cpp session.cpp session-wrapper.cpp s3-uploader.cpp s3-compatible-uploader.cpp mysql-helper.cpp protocol-lws.c

# Compiler flags (include paths for libwebsockets and cJSON)
upload_recordings_CPPFLAGS = $(LIBWEBSOCKETS_CFLAGS) \
  -I/usr/include/lame \
  -I/usr/include/cppconn \
  -I/usr/include/aws-sdk-cpp

# Linker flags (libwebsockets and cJSON)
upload_recordings_LDADD = $(LIBWEBSOCKETS_LIBS) \
  -lmp3lame \
  -lmysqlcppconn \
  -laws-cpp-sdk-s3-crt \
  -laws-cpp-sdk-s3 \
  -laws-cpp-sdk-core \
  -lssl \
  -lcrypto

# Add C++17 support
AM_CXXFLAGS = -std=c++17
AM_LDFLAGS = -L/usr/lib -L/usr/local/lib