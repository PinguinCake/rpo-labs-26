cmake_minimum_required(VERSION 3.22.1)

project("fclient")

add_library(${CMAKE_PROJECT_NAME} SHARED
    native-lib.cpp
)

add_library(spdlog STATIC IMPORTED)
set_target_properties(spdlog PROPERTIES IMPORTED_LOCATION
    "C:/Users/User/AndroidStudioProjects/rpo/libs/spdlog/build/${ANDROID_ABI}/libspdlog.a")

add_library(mbedcrypto SHARED IMPORTED)
set_target_properties(mbedcrypto PROPERTIES IMPORTED_LOCATION
    "C:/Users/User/AndroidStudioProjects/rpo/libs/mbedtls/build/${ANDROID_ABI}/library/libmbedcrypto.so")

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
    "C:/Users/User/AndroidStudioProjects/rpo/libs/spdlog/include"
    "C:/Users/User/AndroidStudioProjects/rpo/libs/mbedtls/include")

target_link_libraries(${CMAKE_PROJECT_NAME}
    spdlog
    mbedcrypto
    android
    log
    ${log-lib}
)