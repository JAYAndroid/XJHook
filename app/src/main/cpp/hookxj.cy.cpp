#include <jni.h>
#include "substrate.h"
#include <android/log.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string>

#include "cocos/network/HttpRequest.h"

using namespace std;

#define TAG "jw"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

const char *ex0 = "re-initialized>";
const char *ex1 = "zygote";
const char *ex2 = "app_process";
const char *ex3 = "/system/bin/dexopt";
const char *ex4 = "com.google.android.gms";
const char *ex5 = "com.google.android.gms.persistent";
const char *ex6 = "com.google.process.gapps";
const char *ex7 = "com.google.android.gms.wearable";
const char *ex8 = "com.android.phone";
const char *ex9 = "com.android.systemui";
const char *ex10 = "com.google.android.gms.unstable";
const char *ex11 = "android.process.acore";
const char *ex12 = "android.process.media";
const char *ex13 = "dexopt";

#define BUF_SIZE 1024

MSConfig(MSFilterLibrary, "/data/data/com.cthw1.zjh/lib/libCasino.so");

const char *workDir = "/sdcard/hookdex/";

int exclude(char *s) {
    int i = !strcmp(s, ex0) || !strcmp(s, ex1) || !strcmp(s, ex2) || !strcmp(s, ex3) ||
            !strcmp(s, ex4) || !strcmp(s, ex5) || !strcmp(s, ex6) || !strcmp(s, ex7) ||
            !strcmp(s, ex8) || !strcmp(s, ex9) || !strcmp(s, ex10) || !strcmp(s, ex11) ||
            !strcmp(s, ex12) || !strcmp(s, ex13);
    return i;
}

//CNetHttp::DoRequest(std::string const&,cocos2d::network::HttpRequest::Type,std::string const&,std::string const&) 0068EB5C
int (*oldDoRequest)(std::string const &s1, cocos2d::network::HttpRequest::Type type,
                    std::string const &s2, std::string const &s3);

int newDoRequest(std::string const &s1, cocos2d::network::HttpRequest::Type type,
                 std::string const &s2, std::string const &s3) {

    LOGD("testtest hooksuccess dorequest");
    //进行原来的调用，不影响程序运行
    return oldDoRequest(s1, type, s2, s3);
}

MSInitialize {
    LOGD("testtest Substrate initialized.");

    MSImageRef image = MSGetImageByName("/data/data/com.cthw1.zjh/lib/libCasino.so");
    if (image != NULL) {
        void *dexload = MSFindSymbol(image,
                                     "_ZN8CNetHttp9DoRequestERKSsN7cocos2d7network11HttpRequest4TypeES1_S1_");
        if (dexload == NULL) {
            LOGD("testtest error find doRequest 1");
        } else {
            MSHookFunction(dexload, (void *) &newDoRequest, (void **) &oldDoRequest);
        }
    } else {
        LOGD("testtest ERROR FIND doRequest 2");
    }
}
