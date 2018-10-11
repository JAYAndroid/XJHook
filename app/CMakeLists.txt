 cmake_minimum_required(VERSION 3.6)

 add_library( # Sets the name of the library.
         hello

         # Sets the library as a shared library.
         SHARED

         # Provides a relative path to your source file(s).
         src/main/cpp/inlineHook.cpp
         src/main/cpp/relocate.cpp
         src/main/cpp/banana/hello.cpp
#         src/main/cpp/hello.cpp
         # X86指令HOOK
#         src/main/cpp/MSHook/MSHook.cpp
#         src/main/cpp/MSHook/util.cpp
#         src/main/cpp/MSHook/Hooker.cpp
#         src/main/cpp/MSHook/Debug.cpp
#         src/main/cpp/MSHook/PosixMemory.cpp
#         src/main/cpp/MSHook/x86.cpp
#         src/main/cpp/MSHook/x86_64.cpp
         )

 #第三方库使用到的头文件
 include_directories(src/main/cpp/cocos/base
         src/main/cpp/cocos/network
         src/main/cpp/cocos/platform
         src/main/cpp/cocos/platform/android
         src/main/cpp/include
         src/main/cpp
         src/main/cpp/MSHook
         )

 # Searches for a specified prebuilt library and stores the path as a
 # variable. Because CMake includes system libraries in the search path by
 # default, you only need to specify the name of the public NDK library
 # you want to add. CMake verifies that the library exists before
 # completing its build.

 find_library( # Sets the name of the path variable.
         log-lib

         # Specifies the name of the NDK library that
         # you want CMake to locate.
         log)


 # add_library(substrate SHARED IMPORTED)
 # set_target_properties(substrate
 #  PROPERTIES IMPORTED_LOCATION
 #  ${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libsubstrate.so)

 #  add_library(substrate-dvm SHARED IMPORTED)
 #  set_target_properties(substrate-dvm
 #    PROPERTIES IMPORTED_LOCATION
 #    ${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libsubstrate-dvm.so)


 target_link_libraries( # Specifies the target library.
         hello

         ${log-lib})




