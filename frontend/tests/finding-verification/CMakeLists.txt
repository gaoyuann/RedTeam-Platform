cmake_minimum_required(VERSION 3.16)
project(FindingVerificationSmoke LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets Network Test)
add_executable(finding-verification-smoke FindingVerificationSmoke.cpp
  ../../src/pages/FindingVerificationDialog.cpp ../../src/pages/FindingVerificationDialog.h
  ../../src/ApiClient.cpp ../../src/ApiClient.h)
target_include_directories(finding-verification-smoke PRIVATE ../../src)
target_link_libraries(finding-verification-smoke Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network Qt5::Test)
enable_testing()
add_test(NAME finding-verification-smoke COMMAND finding-verification-smoke)
set_tests_properties(finding-verification-smoke PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")

add_executable(finding-verification-races FindingVerificationRaces.cpp
  ../../src/pages/FindingVerificationDialog.cpp ../../src/pages/FindingVerificationDialog.h
  ../../src/ApiClient.cpp ../../src/ApiClient.h)
target_include_directories(finding-verification-races PRIVATE ../../src)
target_link_libraries(finding-verification-races Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network Qt5::Test)
foreach(scenario revision dirty-revision reload-in-flight cancel-details close-details cancel-start cancel-start-close cancel-start-destroy single-cancel single-cancel-close single-cancel-destroy single-close-running draft-column draft-refresh draft-switch draft-inflight draft-failed-save draft-deferred template-late-edit preparation-result information-history)
  add_test(NAME finding-verification-${scenario} COMMAND finding-verification-races ${scenario})
  set_tests_properties(finding-verification-${scenario} PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endforeach()
