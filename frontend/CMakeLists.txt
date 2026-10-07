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
    src/LiveActivityPanel.cpp
    src/ToastOverlay.cpp
    src/SplashDialog.cpp
    src/LoginDialog.cpp
    src/CortexPanel.cpp
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
    src/LiveActivityPanel.h
    src/ToastOverlay.h
    src/SplashDialog.h
    src/LoginDialog.h
    src/Theme.h
    src/CortexPanel.h
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

# 把内置的 ROCKEY ARM SDK 动态库拷贝到可执行文件旁，使运行时
# appDir/third_party/rockey/<plat>/<lib> 可解析（dev 构建与安装态均适用）。
add_custom_command(TARGET RedTeam-Platform POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
  "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/rockey"
  "$<TARGET_FILE_DIR:RedTeam-Platform>/third_party/rockey"
  COMMENT "Copying bundled ROCKEY ARM SDK next to binary"
)
