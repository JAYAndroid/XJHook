 cmake_minimum_required(VERSION 3.6)
 add_library( # Sets the name of the library.
         hello
         # Sets the library as a shared library.
         SHARED

         # Provides a relative path to your source file(s).
         #        armeabi-v7a hook公共依赖
         src/main/cpp/inlineHook.cpp
         src/main/cpp/relocate.cpp
         #         香蕉游戏
         src/main/cpp/banana/hello.cpp
         src/main/cpp/banana/lib_json/json_value.cpp
         src/main/cpp/banana/lib_json/json_writer.cpp
         #         当前游戏
         #         src/main/cpp/hello.cpp
         # X86指令hook公共依赖
         #         src/main/cpp/MSHook/MSHook.cpp
         #         src/main/cpp/MSHook/util.cpp
         #         src/main/cpp/MSHook/Hooker.cpp
         #         src/main/cpp/MSHook/Debug.cpp
         #         src/main/cpp/MSHook/PosixMemory.cpp
         #         src/main/cpp/MSHook/x86.cpp
         #         src/main/cpp/MSHook/x86_64.cpp
         )

 #第三方库使用到的头文件
 include_directories(
         #        armeabi-v7a hook公共头文件
         src/main/cpp
         src/main/cpp/include
         #        x86 hook公共头文件
         src/main/cpp/MSHook
         #         香蕉游戏依赖头文件
         src/main/cpp/banana/lib_json
         src/main/cpp/banana/json
 )

 find_library(log-lib log)

 target_link_libraries( # Specifies the target library.
         hello
         ${log-lib})




