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
    src/GlobalSearchDialog.cpp
    src/MainWindow.cpp
    src/SimpleMainWindow.cpp
    src/ApiClient.cpp
    src/ReportFileActions.cpp
    src/WsClient.cpp
    src/CortexPanel.cpp
    src/ToastOverlay.cpp
    src/SplashDialog.cpp
    src/LoginDialog.cpp
    src/pages/BasePage.cpp
    src/pages/DashboardPage.cpp
    src/pages/FlowPage.cpp
    src/pages/TaskAiPanel.cpp
    src/pages/AnalysisPage.cpp
    src/pages/AnalysisHubPage.cpp
    src/pages/ResourceCatalogPage.cpp
    src/pages/TaskPlanPage.cpp
    src/pages/TaskOverviewPage.cpp
    src/pages/TaskLogPanel.cpp
    src/pages/DeployConfigPage.cpp
    src/pages/PlaybookPage.cpp
    src/pages/KnowledgeGraphPage.cpp
    src/pages/FindingVerificationDialog.cpp
    src/pages/ScanPage.cpp
    src/pages/SourceScanDetailDialog.cpp
    src/pages/PayloadPage.cpp
    src/pages/ExecutionPage.cpp
    src/pages/TaskExecutionPanel.cpp
    src/pages/EvaluatePage.cpp
    src/pages/TaskResultsPanel.cpp
    src/pages/ResultsPage.cpp
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
    src/GlobalSearchDialog.h
    src/MainWindow.h
    src/SimpleMainWindow.h
    src/ApiClient.h
    src/ReportFileActions.h
    src/WsClient.h
    src/CortexPanel.h
    src/ToastOverlay.h
    src/SplashDialog.h
    src/LoginDialog.h
    src/AppStyle.h
    src/Theme.h
    src/widgets/WorkbenchTabs.h
    src/widgets/MetricCard.h
    src/widgets/ScanResultOverview.h
    src/pages/BasePage.h
    src/pages/DashboardPage.h
    src/pages/FlowPage.h
    src/pages/TaskAiPanel.h
    src/pages/AnalysisPage.h
    src/pages/AnalysisHubPage.h
    src/pages/ResourceCatalogPage.h
    src/pages/TaskPlanPage.h
    src/pages/TaskOverviewPage.h
    src/pages/TaskLogPanel.h
    src/pages/DeployConfigPage.h
    src/pages/PlaybookPage.h
    src/pages/KnowledgeGraphPage.h
    src/pages/FindingVerificationDialog.h
    src/pages/ScanPage.h
    src/pages/SourceScanDetailDialog.h
    src/pages/PayloadPage.h
    src/pages/ExecutionPage.h
    src/pages/TaskExecutionPanel.h
    src/pages/EvaluatePage.h
    src/pages/TaskResultsPanel.h
    src/pages/ResultsPage.h
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
  set(ROCKEY_SDK_LIBRARY libRockeyARM.so.0.3)
  if(ROCKEY_SDK_ARCH STREQUAL "linux-aarch64")
    set(ROCKEY_SDK_LIBRARY libRockeyARM.so.1.0)
  endif()
  set(ROCKEY_SDK_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/rockey/${ROCKEY_SDK_ARCH}/${ROCKEY_SDK_LIBRARY}")
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

option(BUILD_UI_CHECKS "Build isolated Qt UI regression checks" OFF)
if(BUILD_UI_CHECKS)
  find_package(Qt5 REQUIRED COMPONENTS Test)
  set(UI_CHECK_SOURCES ${SOURCES})
  list(REMOVE_ITEM UI_CHECK_SOURCES src/main.cpp)
  add_executable(RedTeam-Platform-Batch16Checks
    ${UI_CHECK_SOURCES}
    ${HEADERS}
    test/batch16_context_checks.cpp
    resources/resources.qrc
  )
  target_link_libraries(RedTeam-Platform-Batch16Checks
    Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network Qt5::Test
  )
  if(Qt5WebSockets_FOUND)
    target_link_libraries(RedTeam-Platform-Batch16Checks Qt5::WebSockets)
  endif()
  target_include_directories(RedTeam-Platform-Batch16Checks PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  foreach(UI_SCALE IN ITEMS 1 1.25 1.5)
    add_test(NAME ui-context-${UI_SCALE} COMMAND RedTeam-Platform-Batch16Checks)
    set_tests_properties(ui-context-${UI_SCALE} PROPERTIES
      ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_SCALE_FACTOR=${UI_SCALE}"
      TIMEOUT 60
    )
  endforeach()
endif()

if(BUILD_UI_CHECKS)
  add_executable(RedTeam-DashboardChecks
    src/ApiClient.cpp src/pages/DashboardPage.cpp
    test/dashboard_checks.cpp resources/resources.qrc)
  target_include_directories(RedTeam-DashboardChecks PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(RedTeam-DashboardChecks Qt5::Widgets Qt5::Network Qt5::Test)
  add_test(NAME ui-dashboard COMMAND RedTeam-DashboardChecks)
  set_tests_properties(ui-dashboard PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)
endif()

if(BUILD_UI_CHECKS)
  add_executable(RedTeam-FindingPayloadArtifactChecks src/ApiClient.cpp
    src/pages/FindingVerificationDialog.cpp test/finding_payload_artifact_checks.cpp)
  target_include_directories(RedTeam-FindingPayloadArtifactChecks PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(RedTeam-FindingPayloadArtifactChecks Qt5::Widgets Qt5::Network Qt5::Test)
  add_test(NAME ui-finding-payload-artifacts COMMAND RedTeam-FindingPayloadArtifactChecks)
  set_tests_properties(ui-finding-payload-artifacts PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 40)
endif()

if(BUILD_UI_CHECKS)
  add_executable(RedTeam-SourceScanDetailChecks src/ApiClient.cpp
    src/pages/SourceScanDetailDialog.cpp test/source_scan_detail_checks.cpp)
  target_include_directories(RedTeam-SourceScanDetailChecks PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(RedTeam-SourceScanDetailChecks Qt5::Widgets Qt5::Network Qt5::Test)
  foreach(UI_SCALE IN ITEMS 1 1.25 1.5)
    add_test(NAME ui-source-detail-${UI_SCALE} COMMAND RedTeam-SourceScanDetailChecks)
    set_tests_properties(ui-source-detail-${UI_SCALE} PROPERTIES
      ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_SCALE_FACTOR=${UI_SCALE}" TIMEOUT 40)
  endforeach()
endif()

if(BUILD_UI_CHECKS)
  add_executable(RedTeam-GlobalSearchChecks
    src/ApiClient.cpp src/GlobalSearchDialog.cpp
    test/global_search_checks.cpp)
  target_include_directories(RedTeam-GlobalSearchChecks PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(RedTeam-GlobalSearchChecks Qt5::Widgets Qt5::Network Qt5::Test)
  add_test(NAME ui-global-search COMMAND RedTeam-GlobalSearchChecks)
  set_tests_properties(ui-global-search PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)
endif()

if(BUILD_UI_CHECKS)
  add_executable(RedTeam-StatisticsChecks src/ApiClient.cpp test/task_statistics_checks.cpp)
  target_include_directories(RedTeam-StatisticsChecks PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(RedTeam-StatisticsChecks Qt5::Widgets Qt5::Network Qt5::Test)
  add_test(NAME ui-task-statistics COMMAND RedTeam-StatisticsChecks)
  set_tests_properties(ui-task-statistics PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)
endif()

if(BUILD_UI_CHECKS)
  add_executable(RedTeam-TaskReportExportChecks
    src/ApiClient.cpp src/ReportFileActions.cpp src/pages/TaskResultsPanel.cpp
    src/pages/ScanPage.cpp src/pages/SourceScanDetailDialog.cpp src/pages/FindingVerificationDialog.cpp
    test/task_report_export_checks.cpp)
  target_include_directories(RedTeam-TaskReportExportChecks PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(RedTeam-TaskReportExportChecks Qt5::Widgets Qt5::Network Qt5::Test)
  add_test(NAME ui-task-report-export COMMAND RedTeam-TaskReportExportChecks)
  set_tests_properties(ui-task-report-export PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 45)
endif()
