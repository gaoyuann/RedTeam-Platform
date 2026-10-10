find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets Network)
find_package(Qt5WebSockets QUIET)
if(Qt5WebSockets_FOUND)
  message(STATUS "Qt5 WebSockets found — real-time push enabled")
  add_definitions(-DHAS_QT_WEBSOCKETS)
else()
  message(STATUS "Qt5 WebSockets NOT found — real-time push disabled (install libqt5websockets5-dev)")
endif()

set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/SimpleMainWindow.cpp
    src/ApiClient.cpp
    src/WsClient.cpp
    src/CortexPanel.cpp
    src/ToastOverlay.cpp
    src/SplashDialog.cpp
    src/LoginDialog.cpp
    src/pages/BasePage.cpp
    src/pages/FlowPage.cpp
    src/pages/DeployConfigPage.cpp
    src/pages/PlaybookPage.cpp
    src/pages/KnowledgeGraphPage.cpp
    src/pages/ScanPage.cpp
    src/pages/PayloadPage.cpp
    src/pages/ExecutionPage.cpp
    src/pages/EvaluatePage.cpp
    src/pages/SystemPage.cpp
    src/pages/StepIndicator.cpp
    src/pages/PhasePanel.cpp
    src/pages/StatsSummaryCard.cpp
    src/models/TopologyTypes.cpp
    src/pages/TopologyPage.cpp
    src/services/dongle/DongleService.cpp
    src/pages/DongleVerificationPage.cpp
    src/pages/DongleLockPage.cpp
)

set(HEADERS
    src/MainWindow.h
    src/SimpleMainWindow.h
    src/ApiClient.h
    src/WsClient.h
    src/CortexPanel.h
    src/ToastOverlay.h
    src/SplashDialog.h
    src/LoginDialog.h
    src/Theme.h
    src/widgets/WorkbenchTabs.h
    src/widgets/MetricCard.h
    src/widgets/ScanResultOverview.h
    src/pages/BasePage.h
    src/pages/FlowPage.h
    src/pages/DeployConfigPage.h
    src/pages/PlaybookPage.h
    src/pages/KnowledgeGraphPage.h
    src/pages/ScanPage.h
    src/pages/PayloadPage.h
    src/pages/ExecutionPage.h
    src/pages/EvaluatePage.h
    src/pages/SystemPage.h
    src/pages/StepIndicator.h
    src/pages/PhasePanel.h
    src/models/TopologyTypes.h
    src/pages/TopologyPage.h
    src/services/dongle/DongleService.h
    src/pages/DongleVerificationPage.h
    src/pages/DongleLockPage.h
)

add_executable(RedTeam-Platform ${SOURCES} ${HEADERS} resources/resources.qrc)

target_link_libraries(RedTeam-Platform
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    Qt5::Network
)

# Conditionally link WebSockets
if(Qt5WebSockets_FOUND)
  target_link_libraries(RedTeam-Platform Qt5::WebSockets)
endif()

target_include_directories(RedTeam-Platform PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Choose by target architecture (also works with a cross-compilation toolchain).
set(ROCKEY_SDK_ARCH "")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" ROCKEY_PROCESSOR)
  if(ROCKEY_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(ROCKEY_SDK_ARCH linux-aarch64)
  elseif(ROCKEY_PROCESSOR MATCHES "^(x86_64|amd64)$")
    set(ROCKEY_SDK_ARCH linux-x86_64)
  elseif(ROCKEY_PROCESSOR MATCHES "^i[3-6]86$")
    set(ROCKEY_SDK_ARCH linux-x86)
  endif()
endif()
set(ROCKEY_SDK_VALIDATION_ARGS "")
if(ROCKEY_SDK_ARCH)
  set(ROCKEY_SDK_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/rockey/${ROCKEY_SDK_ARCH}/libRockeyARM.so.0.3")
  include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/ValidateRockeySdk.cmake")
  set(ROCKEY_SDK_VALIDATION_ARGS
    COMMAND ${CMAKE_COMMAND}
      "-DROCKEY_SDK_FILE=${ROCKEY_SDK_FILE}"
      "-DROCKEY_SDK_ARCH=${ROCKEY_SDK_ARCH}"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/ValidateRockeySdk.cmake")
endif()

# Run even when no C++ file changed: installing/updating an SDK must not require
# relinking the application before the bundled runtime library is refreshed.
# Avoid TARGET_FILE_DIR here: CMake 3.16 adds a reverse dependency for it.
set(ROCKEY_RUNTIME_DIR "${CMAKE_CURRENT_BINARY_DIR}")
if(CMAKE_CONFIGURATION_TYPES)
  string(APPEND ROCKEY_RUNTIME_DIR "/$<CONFIG>")
endif()
set_target_properties(RedTeam-Platform PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${ROCKEY_RUNTIME_DIR}")
add_custom_target(copy_rockey_sdk
  ${ROCKEY_SDK_VALIDATION_ARGS}
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/rockey"
    "${ROCKEY_RUNTIME_DIR}/third_party/rockey"
  COMMENT "Validating and copying bundled ROCKEY SDK next to binary"
)
add_dependencies(RedTeam-Platform copy_rockey_sdk)
