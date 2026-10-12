cmake_minimum_required(VERSION 3.16)
project(DongleTests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets Network Test)
find_package(Qt5WebSockets QUIET)
enable_testing()
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  message(FATAL_ERROR "The fake SDK tests currently target Linux x86_64")
endif()
add_library(FakeRockey SHARED FakeRockey.cpp)
set_target_properties(FakeRockey PROPERTIES OUTPUT_NAME RockeyARM SUFFIX ".so.0.3"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/third_party/rockey/linux-x86_64")
add_executable(DongleTests DongleTests.cpp ../../src/services/dongle/DongleService.cpp ../../src/pages/DongleVerificationPage.cpp)
target_include_directories(DongleTests PRIVATE ../../src)
target_link_libraries(DongleTests PRIVATE Qt5::Core Qt5::Widgets Qt5::Test)
add_dependencies(DongleTests FakeRockey)
add_test(NAME DongleTests COMMAND DongleTests)
set_tests_properties(DongleTests PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")

# Exercise the actual application windows, keeping the source list in one place.
add_subdirectory(../.. client EXCLUDE_FROM_ALL)
get_target_property(client_sources RedTeam-Platform SOURCES)
get_target_property(client_source_dir RedTeam-Platform SOURCE_DIR)
list(REMOVE_ITEM client_sources src/main.cpp)
list(TRANSFORM client_sources PREPEND "${client_source_dir}/")
add_executable(DongleWindowTests DongleWindowTests.cpp ${client_sources})
target_include_directories(DongleWindowTests PRIVATE ../../src)
target_link_libraries(DongleWindowTests PRIVATE Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network Qt5::Test)
if(Qt5WebSockets_FOUND)
  target_compile_definitions(DongleWindowTests PRIVATE HAS_QT_WEBSOCKETS)
  target_link_libraries(DongleWindowTests PRIVATE Qt5::WebSockets)
endif()
add_dependencies(DongleWindowTests FakeRockey)
add_test(NAME DongleWindowTests COMMAND DongleWindowTests)
set_tests_properties(DongleWindowTests PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")

add_executable(DongleMissingSdkTests DongleMissingSdkTests.cpp ../../src/services/dongle/DongleService.cpp ../../src/pages/DongleVerificationPage.cpp)
target_include_directories(DongleMissingSdkTests PRIVATE ../../src)
target_link_libraries(DongleMissingSdkTests PRIVATE Qt5::Core Qt5::Widgets Qt5::Test)
# Neither the executable directory nor its parent may contain the fake SDK.
set_target_properties(DongleMissingSdkTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/missing-sdk/bin")
add_test(NAME DongleMissingSdkTests COMMAND DongleMissingSdkTests)
set_tests_properties(DongleMissingSdkTests PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")

set(sdk_root "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
foreach(arch linux-x86 linux-x86_64 linux-aarch64)
  set(version 0.3)
  if(arch STREQUAL "linux-aarch64")
    set(version 1.0)
  endif()
  add_test(NAME SdkElf-${arch} COMMAND ${CMAKE_COMMAND}
    "-DROCKEY_SDK_FILE=${sdk_root}/third_party/rockey/${arch}/libRockeyARM.so.${version}"
    "-DROCKEY_SDK_ARCH=${arch}" -DROCKEY_SDK_REQUIRED=ON
    -P "${sdk_root}/cmake/ValidateRockeySdk.cmake")
endforeach()
add_test(NAME SdkElf-reject-wrong-architecture COMMAND ${CMAKE_COMMAND}
  "-DROCKEY_SDK_FILE=${sdk_root}/third_party/rockey/linux-x86_64/libRockeyARM.so.0.3"
  -DROCKEY_SDK_ARCH=linux-aarch64 -DROCKEY_SDK_REQUIRED=ON
  -P "${sdk_root}/cmake/ValidateRockeySdk.cmake")
set_tests_properties(SdkElf-reject-wrong-architecture PROPERTIES WILL_FAIL TRUE)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME DonglePackagingTests COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/test_packaging.py")
