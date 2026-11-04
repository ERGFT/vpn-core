# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.20)
project(vpn_core_sdk_consumer LANGUAGES C CXX)

if(NOT DEFINED VPN_CORE_SDK_ROOT)
  message(FATAL_ERROR "VPN_CORE_SDK_ROOT must point to an extracted SDK")
endif()
if(NOT DEFINED VPN_CORE_LINKAGE)
  set(VPN_CORE_LINKAGE shared)
endif()

find_package(vpn-core CONFIG REQUIRED
  PATHS "${VPN_CORE_SDK_ROOT}/cmake"
  NO_DEFAULT_PATH
)

if(NOT TARGET "vpn-core::${VPN_CORE_LINKAGE}")
  message(FATAL_ERROR "SDK does not provide vpn-core::${VPN_CORE_LINKAGE}")
endif()

add_executable(vpn-core-sdk-consumer "${VPN_CORE_SDK_ROOT}/examples/minimal.c")
target_link_libraries(vpn-core-sdk-consumer PRIVATE "vpn-core::${VPN_CORE_LINKAGE}")

add_executable(vpn-core-sdk-consumer-cpp cpp_consumer.cpp)
target_link_libraries(vpn-core-sdk-consumer-cpp PRIVATE "vpn-core::${VPN_CORE_LINKAGE}")
