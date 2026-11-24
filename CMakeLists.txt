cmake_minimum_required(VERSION 3.20)
project(EvanProxy LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

# 1. ZTzTopia/enet (Growtopia-compatible ENet with usingNewPacket / usingNewPacketForServer)
FetchContent_Declare(
    enet_src
    URL https://github.com/ZTzTopia/enet/archive/refs/heads/master.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(enet_src)
target_include_directories(enet BEFORE PUBLIC "${enet_src_SOURCE_DIR}/include")

# 2. Mbed-TLS 3.6.8 LTS (pre-generated sources, static build)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    mbedtls_src
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.8/mbedtls-3.6.8.tar.bz2
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(mbedtls_src)

add_library(evanproxy_core STATIC
    src/config.cpp
    src/hosts.cpp
    src/dns.cpp
    src/cert.cpp
    src/banner.cpp
    src/protocol.cpp
    src/packet_logger.cpp
    src/items_db.cpp
    src/session.cpp
    src/ui_menu.cpp
    src/http_bridge.cpp
    src/enet_proxy.cpp
    src/proxy_controller.cpp
    src/overlay_hud.cpp
    src/desktop_gui.cpp
)

target_include_directories(evanproxy_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_definitions(evanproxy_core PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)
target_link_libraries(evanproxy_core PUBLIC
    enet
    MbedTLS::mbedtls
    MbedTLS::mbedx509
    MbedTLS::mbedcrypto
    ws2_32
    winmm
    dwmapi
    bcrypt
    crypt32
    shell32
    gdiplus
    gdi32
    user32
)

add_executable(EvanProxy EvanProxy.cpp)
target_link_libraries(EvanProxy PRIVATE evanproxy_core)

add_executable(evanproxy_tests tests/test_proxy.cpp)
target_link_libraries(evanproxy_tests PRIVATE evanproxy_core)

if(MINGW)
    target_link_options(EvanProxy PRIVATE -static-libgcc -static-libstdc++ -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic)
    target_link_options(evanproxy_tests PRIVATE -static-libgcc -static-libstdc++ -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic)
endif()
