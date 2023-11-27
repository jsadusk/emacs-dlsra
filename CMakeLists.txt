cmake_minimum_required(VERSION 3.7...3.27)
if(${CMAKE_VERSION} VERSION_LESS 3.12)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

project(EmacsDLSRA VERSION 0.1
  DESCRIPTION "Emacs Direct libssh remote access"
  LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
  
add_library(dlsra SHARED src/emacs-dlsra.c hashtable/hashtable.c emacs-modules/emacs-module-helpers.c)

find_program(emacs_executable emacs)
get_filename_component(emacs_bin_dir ${emacs_executable} DIRECTORY)
set(emacs_include ${emacs_bin_dir}/../include)

target_include_directories(dlsra SYSTEM BEFORE PUBLIC ${emacs_include} hashtable emacs-modules)
target_compile_options(dlsra PUBLIC "-fPIC")
set_target_properties(dlsra PROPERTIES PREFIX "")
set_target_properties(dlsra PROPERTIES SUFFIX ".so")

find_package(LIBSSH)
if (LIBSSH_FOUND)
  target_include_directories(dlsra SYSTEM AFTER PUBLIC ${LIBSSH_INCLUDE_DIR})
  target_link_libraries(dlsra PRIVATE ssh)
else ()
  message(FATAL_ERROR "Unable to find libssh")
endif ()

