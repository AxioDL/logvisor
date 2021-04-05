if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.10 FATAL_ERROR) # because of c++17
  project(nod VERSION 0.1)
  if (NOT MSVC)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
  endif()
endif()

include (CMakePackageConfigHelpers)

add_subdirectory(fmt)

add_library(logvisor
            lib/logvisor.cpp
            include/logvisor/logvisor.hpp)

if ("${SENTRY_DSN}" STREQUAL "")
  message(STATUS "SENTRY_DSN not set, not enabling Sentry")
  target_compile_definitions(logvisor PUBLIC SENTRY_ENABLED=0)
  set(SENTRY_LIB "")
  set(BREAKPAD_CLIENT "")
else()
  message(STATUS "Enabling Sentry integration")
  add_subdirectory(sentry)
  target_compile_definitions(logvisor PUBLIC SENTRY_ENABLED=1)
  target_compile_definitions(logvisor PRIVATE SENTRY_DSN="${SENTRY_DSN}")
  set(SENTRY_LIB sentry)
  if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(BREAKPAD_CLIENT breakpad_client)
    target_compile_options(breakpad_client PRIVATE "-Wno-implicit-fallthrough")
    target_compile_options(sentry PRIVATE "-Wno-implicit-fallthrough")
    set_property(TARGET breakpad_client PROPERTY CXX_STANDARD 17)
    set_property(TARGET sentry PROPERTY CXX_STANDARD 17)
  else ()
    set(BREAKPAD_CLIENT "")
  endif ()
endif ()

target_link_libraries(logvisor PUBLIC fmt ${SENTRY_LIB})
if(NX)
  target_link_libraries(logvisor PUBLIC debug nxd optimized nx)
else()
  target_link_libraries(logvisor PUBLIC ${CMAKE_DL_LIBS})
endif()

target_include_directories(logvisor PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

install(DIRECTORY include/logvisor DESTINATION include)
install(DIRECTORY fmt/include/fmt DESTINATION include)

set(version_config_file "${PROJECT_BINARY_DIR}/logvisorConfigVersion.cmake")
set(config_file "${PROJECT_BINARY_DIR}/logvisorConfig.cmake")
set(config_install_dir "lib/cmake/logvisor")

# Associate target with export
install(
    TARGETS logvisor fmt ${SENTRY_LIB} ${BREAKPAD_CLIENT}
    EXPORT logvisorTargets
    ARCHIVE DESTINATION "lib"
    INCLUDES DESTINATION include  # This sets the INTERFACE_INCLUDE_DIRECTORIES property of the target.
)

# Install the target config files
install(
    EXPORT logvisorTargets
    NAMESPACE "logvisor::"
    DESTINATION "${config_install_dir}"
)

# Generate version config file
write_basic_package_version_file(
    "${version_config_file}"
    COMPATIBILITY SameMajorVersion
)

# Generate config file
configure_package_config_file(
    "Config.cmake.in"
    "${config_file}"
    INSTALL_DESTINATION "lib/cmake/logvisor"
)

# Install the config files
install(
    FILES "${config_file}" "${version_config_file}"
    DESTINATION ${config_install_dir}
)
