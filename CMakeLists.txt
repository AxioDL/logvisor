cmake_minimum_required(VERSION 3.10 FATAL_ERROR) # because of c++17
project(nod VERSION 0.1)
if (NOT MSVC)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif ()

include (CMakePackageConfigHelpers)

if (NOT TARGET fmt)
  add_subdirectory(fmt)
  target_compile_definitions(fmt PUBLIC
      FMT_ARM_ABI_COMPATIBILITY=1
      FMT_EXCEPTIONS=0)
  target_compile_definitions(fmt INTERFACE
      FMT_ENFORCE_COMPILE_STRING=1
      FMT_UNICODE=1)
  set(FMT_LIB fmt)
endif ()

add_library(logvisor
            lib/logvisor.cpp
            include/logvisor/logvisor.hpp)

if ("${SENTRY_DSN}" STREQUAL "")
  message(STATUS "SENTRY_DSN not set, not enabling Sentry")
  target_compile_definitions(logvisor PUBLIC SENTRY_ENABLED=0)
  set(SENTRY_LIB "")
  set(BREAKPAD_CLIENT "")
else ()
  message(STATUS "Enabling Sentry integration")
  include(FetchContent)
  FetchContent_Declare(sentry
      GIT_REPOSITORY https://github.com/getsentry/sentry-native.git
      GIT_TAG 5fcb1dc4d1c8b85fc5ab225d29c7394b375fd1e9
  )
  FetchContent_MakeAvailable(sentry)
  target_compile_definitions(logvisor PUBLIC SENTRY_ENABLED=1)
  target_compile_definitions(logvisor PRIVATE SENTRY_DSN="${SENTRY_DSN}")
  set(SENTRY_LIB sentry)
  if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(BREAKPAD_CLIENT breakpad_client)
    target_compile_options(breakpad_client PRIVATE -Wno-implicit-fallthrough -Wno-array-bounds)
    target_compile_options(sentry PRIVATE "-Wno-implicit-fallthrough")
    set_property(TARGET breakpad_client PROPERTY CXX_STANDARD 17)
    set_property(TARGET sentry PROPERTY CXX_STANDARD 17)
  else ()
    set(BREAKPAD_CLIENT "")
  endif ()
  if (MSVC)
    target_compile_options(crashpad_client PRIVATE "/W0")
    target_compile_options(crashpad_util PRIVATE "/W0")
    target_compile_options(crashpad_snapshot PRIVATE "/W0")
    target_compile_options(mini_chromium PRIVATE "/W0")
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      target_compile_options(crashpad_zlib PRIVATE "-mpclmul")
    endif ()
  endif ()
endif ()

target_link_libraries(logvisor PUBLIC fmt ${SENTRY_LIB})
if(NX)
  target_link_libraries(logvisor PUBLIC debug nxd optimized nx)
else()
  target_link_libraries(logvisor PUBLIC ${CMAKE_DL_LIBS})
endif()

target_include_directories(logvisor PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
install(DIRECTORY include/logvisor DESTINATION include)
if (FMT_LIB)
  install(DIRECTORY fmt/include/fmt DESTINATION include)
endif ()

set(version_config_file "${PROJECT_BINARY_DIR}/logvisorConfigVersion.cmake")
set(config_file "${PROJECT_BINARY_DIR}/logvisorConfig.cmake")
set(config_install_dir "lib/cmake/logvisor")

# Associate target with export
install(
    TARGETS logvisor ${FMT_LIB} ${SENTRY_LIB} ${BREAKPAD_CLIENT}
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
endif()
