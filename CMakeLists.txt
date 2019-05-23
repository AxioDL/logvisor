include_directories(include)
add_library(logvisor
            lib/logvisor.cpp
            include/logvisor/logvisor.hpp)

set(LOGVISOR_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include CACHE PATH "logvisor include path" FORCE)

install(DIRECTORY include/logvisor DESTINATION include) 
