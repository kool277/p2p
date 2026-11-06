# The CMake package for libqalqon. `find_package(qalqon)` gives qalqon::qalqon.
#
# Build the library first with `cargo build -p qalqon-ffi`. A release profile is refused
# until the certified library replaces the test-only provider.
cmake_minimum_required(VERSION 3.16)
project(qalqon VERSION 0.0.0 LANGUAGES C CXX)

set(QALQON_LIBRARY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../target/debug" CACHE PATH "Where cargo put libqalqon")

add_library(qalqon STATIC IMPORTED GLOBAL)
set_target_properties(qalqon PROPERTIES
    IMPORTED_LOCATION "${QALQON_LIBRARY_DIR}/libqalqon.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include"
    INTERFACE_LINK_LIBRARIES "pthread;dl;m")
add_library(qalqon::qalqon ALIAS qalqon)

include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/qalqon-config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/qalqon-config.cmake"
    INSTALL_DESTINATION lib/cmake/qalqon)
install(FILES "${QALQON_LIBRARY_DIR}/libqalqon.a" DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/qalqon-config.cmake" DESTINATION lib/cmake/qalqon)
