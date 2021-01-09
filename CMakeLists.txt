cmake_minimum_required(VERSION 3.17)
project(su_ruby_decryptor C)

set(CMAKE_C_STANDARD 11)

add_executable(su_ruby_decryptor main.c)
target_link_libraries(su_ruby_decryptor Crypt32)