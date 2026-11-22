cmake_minimum_required(VERSION 3.16)
project(MedicalIoTThreePartySimulation LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(tps tps.cpp)
target_link_libraries(tps PRIVATE OpenSSL::Crypto Threads::Threads)
target_compile_options(tps PRIVATE -Wall -Wextra)
