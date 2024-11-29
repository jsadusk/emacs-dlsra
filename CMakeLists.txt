cmake_minimum_required(VERSION 3.7...3.27)
if(${CMAKE_VERSION} VERSION_LESS 3.12)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

project(TrampLibSSH VERSION 0.1
  DESCRIPTION "Emacs tramp libssh backend"
  LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
  
add_library(emacs-libssh SHARED src/emacs-libssh.c hashtable/hashtable.c emacs-modules/emacs-module-helpers.c)
add_executable(test_stat src/test_stat.c)

find_program(emacs_executable emacs)
get_filename_component(emacs_bin_dir ${emacs_executable} DIRECTORY)
set(emacs_include ${emacs_bin_dir}/../include)

target_include_directories(emacs-libssh SYSTEM BEFORE PUBLIC ${emacs_include} hashtable emacs-modules)
target_compile_options(emacs-libssh PUBLIC "-fPIC")
set_target_properties(emacs-libssh PROPERTIES PREFIX "")
set_target_properties(emacs-libssh PROPERTIES SUFFIX ".so")

find_package(LIBSSH)
if (LIBSSH_FOUND)
  target_include_directories(emacs-libssh SYSTEM AFTER PUBLIC ${LIBSSH_INCLUDE_DIR})
  target_link_libraries(emacs-libssh PRIVATE ssh)
  target_include_directories(test_stat SYSTEM AFTER PUBLIC ${LIBSSH_INCLUDE_DIR})
  target_link_libraries(test_stat PRIVATE ssh)
else ()
  message(FATAL_ERROR "Unable to find libssh")
endif ()

