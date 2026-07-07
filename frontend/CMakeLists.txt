find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets Network Sql)

set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
)

set(HEADERS
    src/MainWindow.h
)

add_executable(RedTeam-Platform ${SOURCES} ${HEADERS})

target_link_libraries(RedTeam-Platform
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    Qt5::Network
    Qt5::Sql
)
