# CMake alternative (requires cmake 3.16+; Makefile is primary for v0.1).
cmake_minimum_required(VERSION 3.16)
project(c-whatsapp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wpedantic)

include_directories(include)

add_library(cwa_lib
  src/binary.c
  src/auth.c
  src/crypto.c
  src/noise.c
  src/pb.c
  src/ws.c
  src/pairing.c
  src/socket.c
  src/send.c
  src/qr.c
)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_library(SODIUM_LIB sodium REQUIRED)
find_library(QRENCODE_LIB qrencode REQUIRED)
target_link_libraries(cwa_lib OpenSSL::Crypto ZLIB::ZLIB ${SODIUM_LIB} ${QRENCODE_LIB})

add_executable(c-whatsapp src/main.c)
target_link_libraries(c-whatsapp cwa_lib)

enable_testing()
add_executable(test_binary tests/test_binary.c)
target_link_libraries(test_binary cwa_lib)
add_test(NAME binary COMMAND test_binary)

add_executable(test_auth tests/test_auth.c)
target_link_libraries(test_auth cwa_lib)
add_test(NAME auth COMMAND test_auth)

add_executable(test_noise tests/test_noise.c)
target_link_libraries(test_noise cwa_lib)
add_test(NAME noise COMMAND test_noise)

add_executable(test_pb tests/test_pb.c)
target_link_libraries(test_pb cwa_lib)
add_test(NAME pb COMMAND test_pb)
