find_package(Qt5 REQUIRED COMPONENTS Widgets Network Sql)
add_library(PentagiSourceScan STATIC
    src/models/SourceScanTypes.cpp
    src/services/source_scan/SourceScanStore.cpp
    src/services/source_scan/SourceScanService.cpp
    src/services/pentagi/PentagiService.cpp
    src/services/openai/OpenAiCompatibleService.cpp
    src/network/HttpClient.cpp
    src/config/AppConfig.cpp
    src/config/ConfigManager.cpp
    src/ui/pages/source_scan/SourceScanPage.cpp
)
target_include_directories(PentagiSourceScan PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(PentagiSourceScan PUBLIC Qt5::Widgets Qt5::Network Qt5::Sql)
# Link the resource directly into consumers so static-library dead stripping
# cannot remove the SQLite schema.
target_sources(PentagiSourceScan INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/services/source_scan/source_scan_schema.qrc)
if(BUILD_UI_CHECKS)
    find_package(Qt5 REQUIRED COMPONENTS Test)
    add_executable(PentagiSourceScanChecks tests/SourceScanTests.cpp)
    target_link_libraries(PentagiSourceScanChecks PRIVATE PentagiSourceScan Qt5::Test)
    add_test(NAME pentagi-source-scan COMMAND PentagiSourceScanChecks)
    set_tests_properties(pentagi-source-scan PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 180)
endif()
