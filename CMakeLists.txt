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

if(APPLE OR UNIX)
  include(ExternalProject)
  find_package(Git REQUIRED)
  find_program(MAKE_EXE NAMES gmake make)
  ExternalProject_Add(
          project_libbacktrace
          PREFIX ${PROJECT_BINARY_DIR}/libbacktrace
          GIT_REPOSITORY https://github.com/status-im/libbacktrace.git
          GIT_TAG 2e878a38dd7144c84b665019b1085ea38ebe56d1
          CONFIGURE_COMMAND ${PROJECT_BINARY_DIR}/libbacktrace/src/project_libbacktrace/configure --enable-host-shared --prefix=${PROJECT_BINARY_DIR}/libbacktrace/install --enable-shared=no --enable-static=yes
          BUILD_COMMAND ${MAKE_EXE}
          INSTALL_COMMAND ${MAKE_EXE} install
          BUILD_IN_SOURCE 1
  )
  add_library(libbacktrace STATIC IMPORTED GLOBAL)
  set_target_properties(libbacktrace PROPERTIES IMPORTED_LOCATION "${PROJECT_BINARY_DIR}/libbacktrace/install/lib/libbacktrace.a")
  set_target_properties(libbacktrace PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_BINARY_DIR}/libbacktrace/install/include")
  # Hack for INTERFACE_INCLUDE_DIRECTORIES propagation
  # https://gitlab.kitware.com/cmake/cmake/-/issues/15052
  file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/libbacktrace/install/include")
  add_dependencies(libbacktrace project_libbacktrace)
  set(BACKTRACE_LIBS libbacktrace)
else()
  set(BACKTRACE_LIBS "")
endif()

target_link_libraries(logvisor PUBLIC fmt)
if(NX)
    target_link_libraries(logvisor PUBLIC debug nxd optimized nx)
else()
    target_link_libraries(logvisor PRIVATE ${CMAKE_DL_LIBS} ${BACKTRACE_LIBS})
endif()
target_include_directories(logvisor PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

install(DIRECTORY include/logvisor DESTINATION include)
install(DIRECTORY fmt/include/fmt DESTINATION include)

set(version_config_file "${PROJECT_BINARY_DIR}/logvisorConfigVersion.cmake")
set(config_file "${PROJECT_BINARY_DIR}/logvisorConfig.cmake")
set(config_install_dir "lib/cmake/logvisor")

# Associate target with export
install(
    TARGETS logvisor fmt
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
