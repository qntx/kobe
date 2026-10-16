project(V1Probe)
cmake_minimum_required(VERSION 3.16)

set(PACKAGE_NAME V1Probe)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

file(GLOB_RECURSE shared_files CONFIGURE_DEPENDS RELATIVE ${CMAKE_SOURCE_DIR}
     "../cpp/**.cpp" "src/main/cpp/**.cpp"
)

add_library(${PACKAGE_NAME} SHARED ${shared_files})

# Add Nitrogen specs :)
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/V1Probe+autolinking.cmake)

include_directories(
        "../cpp"
)

# Same Hermes link pattern as react-native-worklets 0.10.1: the hermes-engine
# prefab target is hermesvm on RN >= 0.82 and libhermes before that.
find_package(hermes-engine REQUIRED CONFIG)

find_library(LOG_LIB log)

target_link_libraries(
        ${PACKAGE_NAME}
        ${LOG_LIB}
        android
)

if(ReactAndroid_VERSION_MINOR GREATER_EQUAL 82)
  target_link_libraries(${PACKAGE_NAME} hermes-engine::hermesvm)
else()
  target_link_libraries(${PACKAGE_NAME} hermes-engine::libhermes)
endif()
