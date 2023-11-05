cmake_minimum_required(VERSION 3.24)
project(banning-e2ee-is-stupid)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)

FetchContent_Declare(Sodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG 99f14233eab1d4f7f49c2af4ec836f2e701c445e # HEAD as of 2022-05-28
)
set(SODIUM_DISABLE_TESTS ON)
FetchContent_MakeAvailable(Sodium)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/third_party/SQLiteCpp)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/third_party/CLI11)

add_executable(banning-e2ee-is-stupid main.cc)
target_link_libraries(banning-e2ee-is-stupid
  PRIVATE
  SQLiteCpp
  sqlite3
  sodium 
  CLI11::CLI11
  )

