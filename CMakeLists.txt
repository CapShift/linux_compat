cmake_minimum_required(VERSION 3.23)
project(linux_compat C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

add_library(linux_compat STATIC
	src/sendfile.c
	src/prctl.c)
target_include_directories(linux_compat PUBLIC include)
target_compile_definitions(linux_compat PRIVATE -D_GNU_SOURCE)
target_compile_options(linux_compat PRIVATE
	-Wall -Wextra -Werror
	-ffunction-sections -fdata-sections)

install(TARGETS linux_compat DESTINATION lib)
