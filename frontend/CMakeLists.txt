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
    src/SimpleMainWindow.cpp
    src/ApiClient.cpp
    src/WsClient.cpp
    src/LiveActivityPanel.cpp
    src/ToastOverlay.cpp
    src/SplashDialog.cpp
    src/LoginDialog.cpp
    src/pages/BasePage.cpp
    src/pages/DashboardPage.cpp
    src/pages/DeployConfigPage.cpp
    src/pages/PlaybookPage.cpp
    src/pages/ScanPage.cpp
    src/pages/PayloadPage.cpp
    src/pages/ExecutionPage.cpp
    src/pages/EvaluatePage.cpp
    src/pages/SystemPage.cpp
    src/models/TopologyTypes.cpp
    src/pages/TopologyPage.cpp
)

set(HEADERS
    src/SimpleMainWindow.h
    src/ApiClient.h
    src/WsClient.h
    src/LiveActivityPanel.h
    src/ToastOverlay.h
    src/SplashDialog.h
    src/LoginDialog.h
    src/Theme.h
    src/pages/BasePage.h
    src/pages/DashboardPage.h
    src/pages/DeployConfigPage.h
    src/pages/PlaybookPage.h
    src/pages/ScanPage.h
    src/pages/PayloadPage.h
    src/pages/ExecutionPage.h
    src/pages/EvaluatePage.h
    src/pages/SystemPage.h
    src/models/TopologyTypes.h
    src/pages/TopologyPage.h
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
