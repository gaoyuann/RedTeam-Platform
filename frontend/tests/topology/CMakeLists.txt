cmake_minimum_required(VERSION 3.16)
project(TopologySmoke LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets Network)
add_executable(topology-smoke TopologySmoke.cpp
  ../../src/pages/TopologyPage.cpp ../../src/pages/TopologyPage.h
  ../../src/models/TopologyTypes.cpp
  ../../src/ApiClient.cpp ../../src/ApiClient.h)
target_include_directories(topology-smoke PRIVATE ../../src)
target_link_libraries(topology-smoke Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network)
enable_testing()
add_test(NAME topology-smoke COMMAND topology-smoke)
set_tests_properties(topology-smoke PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
