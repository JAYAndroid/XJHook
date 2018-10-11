#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <sys/mman.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<errno.h>
#include <fcntl.h>
#include<time.h>
#include<sys/socket.h>
#include<pthread.h>
#include<netinet/in.h>
#include<netinet/tcp.h>
#include<jni.h>
#include<string>
#include"inlineHook.h"
#include<vector>
#include<map>
#include "banana/json/json.h"



//using namespace std;
#define FIFO  "/sdcard/fifo_file"
#define MAXLINE 4048
#define LOG_TAG "DEBUG"
#define PROT_ALL PROT_READ|PROT_WRITE|PROT_EXEC
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
uint32_t base;

int (*_CSocket_Send)(void *handle, char const *c, int value);

std::string (*_Json_FastWriter_write)(void *handle, Json::Value const &value);


int (*_CSocket_Recv)(void *handle, char *c, int value);

void *get_module_base(pid_t pid, const char *module_name) {

    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];
    if (pid < 0) {

        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }
    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);

                if (addr == 0x8000)
                    addr = 0;
                break;
            }
        }
        fclose(fp);
    }


    return (void *) addr;
}

char *readFile(const char *filePath, int *destLen) {
    FILE *pFile = fopen(filePath, "rb");
    char *pBuf;
    fseek(pFile, 0, SEEK_END);
    int len = ftell(pFile);
    *destLen = len;
    pBuf = new char[len];
    rewind(pFile);
    fread(pBuf, len, 1, pFile);
    fclose(pFile);
    return pBuf;
}

std::string readfile(std::string path) {
    int destlen;
    char *p = readFile(path.c_str(), &destlen);
    return std::string(p, destlen);


}

typedef unsigned short ushort;
typedef unsigned char uchar;
int pos, len;
void *g_cmdhandle = NULL;
void *g_cmdhandle0 = NULL;
int gethandle = 0;


int cli_sockfd = -1;
int g_cmd, g_ver, g_gameid;


#define lua_newtable(L) lua_createtable(L,0,0)
#define lua_pushcfunction(L, f)  lua_pushcclosure(L, (f), 0)
#define LUA_GLOBALSINDEX    (-10002)
#define LUA_MULTRET    (-1)
#define lua_setglobal(L, s)  lua_setfield(L, LUA_GLOBALSINDEX, (s))
#define lua_register(L, n, f) (lua_pushcfunction(L, (f)), lua_setglobal(L, (n)))
#define lua_getglobal(L, s)  lua_getfield(L, LUA_GLOBALSINDEX, (s))
#define lua_tostring(L, i)   lua_tolstring(L, (i), NULL)
#define luaL_dostring(L, s) (luaL_loadstring(L, s) || lua_pcall(L, 0, LUA_MULTRET, 0))


//sub_6F4134
std::string &
replace_all_distinct(std::string &str, const std::string &old_value, const std::string &new_value) {
    for (std::string::size_type pos(0); pos != std::string::npos; pos += new_value.length()) {
        if ((pos = str.find(old_value, pos)) != std::string::npos)
            str.replace(pos, old_value.length(), new_value);
        else
            break;
    }
    return str;
}

void SplitString(const std::string &s, std::vector<std::string> &v, const std::string &c) {
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while (std::string::npos != pos2) {
        v.push_back(s.substr(pos1, pos2 - pos1));

        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if (pos1 != s.length())
        v.push_back(s.substr(pos1));
}

std::vector<std::string> rule;

std::string rulerep(char *t, int len) {

    std::string str = std::string(t, len);
    for (auto i = rule.begin(); i != rule.end(); i++) {
        std::vector<std::string> v;
        SplitString(*i, v, "|");
        char *end;
        int pos;
        int vlen = static_cast<int>(strtol(v[0].c_str(), &end, 10));
        if (str.length() - 4 > vlen && (pos = str.find(v[1])) != std::string::npos) {
            //str.replace(pos, v[1].length(), v[2]);
            str = replace_all_distinct(str, v[1], v[2]);
        }
    }
    return str;

}


void *L;
void *NT = NULL;
typedef struct _pp {
    int x;
    int y;
} pp;
std::map<int, pp> fipo;
pthread_mutex_t mutex;

std::map<int, int> select_fish;

int g_mode = 0;

int hook_CSocket_Send(void *handle, char const *str, int len) {
    LOGD("----------testtest hook csocket_send success-------------");
    LOGD("testtest socket send data = %s, value = %d", str, len);
    LOGD("----------------------testtest------------------------------");
    char *buf;
    int *pi;
    g_cmdhandle = handle;
    if (str && len) {
        buf = (char *) malloc(len + 4);
        pi = (int *) buf;
        pi[0] = 1;// 发包
        if (len)memcpy(buf + 4, str, len);
        std::string ts = rulerep(buf, len + 8);
        if (cli_sockfd != -1) {
            send(cli_sockfd, ts.c_str(), ts.length(), 0);
        }
        free(buf);
        char *pnew = (char *) ts.c_str();
        pnew += 4;
        return _CSocket_Send(handle, pnew, ts.length() - 8);
    }
    return _CSocket_Send(handle, str, len - 4);
}

int fir_sendcmd(char *cmd, int cmdlen) {
    char *pt;

    if (cmd == NULL || cmdlen <= 0) {
        return -1;
    } else {
        cmdlen = cmdlen - 4;
        pt = cmd + 4;

        LOGD("testtest execute cmd = %s", cmd);

        //发送数据
        if (!memcmp(cmd, "send", 4)) {
            if (g_cmdhandle)hook_CSocket_Send(g_cmdhandle, pt, cmdlen);
        }

        //添加规则
        if (!memcmp(cmd, "rule", 4)) {
            rule.push_back(std::string(pt, cmdlen));
        }

        if (!memcmp(cmd, "dule", 4))  //清空规则
        {
            rule.clear();
        }

    }

    return 0;

}

//int fir_sendcmd(char *cmd, int cmdlen) {
//    ushort *pi;
//    char *pt;
//    int t;
//    int msg[7];
//    int *pos;
//    std::string data;
//
//    LOGD("testtest 收到指令 = %s", cmd);
//
//    if (cmd == NULL || cmdlen <= 0) {
//        return -1;
//    } else {
//        cmdlen = cmdlen - 4;
//        pi = (ushort *) (cmd + 4);
//        pt = cmd + 4;
//        pos = (int *) (cmd + 4);
//        data = pt;
//        if (!memcmp(cmd, "send", 4))  //发送数据
//        {
//            int newstr[10];
//            newstr[6] = (int) (pt + 4);
//
//            if (g_cmdhandle) {
//                _Json_FastWriter_write(g_cmdhandle, data);
//                LOGD("testtest 数据重发 = %s", pt);
//            }
//
//        }
//        if (!memcmp(cmd, "rule", 4))  //添加规则
//        {
//            rule.push_back(std::string((char *) pt, cmdlen));
//
//        }
//        if (!memcmp(cmd, "dule", 4))  //清空规则
//        {
//            rule.clear();
//
//        }
//        if (!memcmp(cmd, "fish", 4)) {
//            std::string str = readfile("/sdcard/Misc/in.lua");
//            str += '\x00';
////            NT = lua_newthread(L);
////            luaL_dostring(NT, (char *) str.c_str());
//            //luaL_dostring(NT,"local file = io.open(\"/sdcard/cj.log\", \"w+b\")\nio.close(file)");
//        }
//        if (!memcmp(cmd, "fipo", 4)) {
//            pthread_mutex_lock(&mutex);
//            pp point;
//            point.x = pos[1];
//            point.y = pos[2];
//            fipo[pos[0]] = point;
//
//            pthread_mutex_unlock(&mutex);
//            //luaL_dostring(NT,"local file = io.open(\"/sdcard/cj.log\", \"w+b\")\nio.close(file)");
//            LOGD("testtest fipo %d %d %d", pos[0], pos[1], pos[2]);
//        }
//        if (!memcmp(cmd, "fipo", 4)) {
//            pthread_mutex_lock(&mutex);
//            pp point;
//            point.x = pos[1];
//            point.y = pos[2];
//            fipo[pos[0]] = point;
//
//            pthread_mutex_unlock(&mutex);
//            //luaL_dostring(NT,"local file = io.open(\"/sdcard/cj.log\", \"w+b\")\nio.close(file)");
//            LOGD("testtest fipo %d %d %d", pos[0], pos[1], pos[2]);
//        }
//
//        if (!memcmp(cmd, "fise", 4)) {
//            pthread_mutex_lock(&mutex);
//
//            select_fish[pos[0]] = pos[0];
//
//            pthread_mutex_unlock(&mutex);
//            //luaL_dostring(NT,"local file = io.open(\"/sdcard/cj.log\", \"w+b\")\nio.close(file)");
//            LOGD("testtest fise %d", pos[0]);
//        }
//
//        if (!memcmp(cmd, "mod1", 4)) {
//
//            pthread_mutex_lock(&mutex);
//            g_mode = 0;
//            select_fish.clear();
//            fipo.clear();
//            pthread_mutex_unlock(&mutex);
//            LOGD("testtest switch  mode1");
//
//
//            //luaL_dostring(NT,"local file = io.open(\"/sdcard/cj.log\", \"w+b\")\nio.close(file)");
//        }
//        if (!memcmp(cmd, "mod2", 4)) {
//            pthread_mutex_lock(&mutex);
//            g_mode = 1;
//            select_fish.clear();
//            fipo.clear();
//            pthread_mutex_unlock(&mutex);
//            LOGD("testtest switch  mode2");
//
//        }
//
//
//        LOGD("testtest execute cmd");
//
//
//    }
//
//    return 0;
//
//}

#define PORT 6666

int cmd_server() {

    int ser_sockfd;
    int err, n;
    int addlen;
    struct sockaddr_in ser_addr;
    struct sockaddr_in cli_addr;
    fd_set rfd;
    int enable = 1;
    char recvline[1024], sendline[1024];

    ser_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (ser_sockfd == -1) {
        LOGD("testtest socket error:%s\n", strerror(errno));
        return -1;
    }

    bzero(&ser_addr, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ser_addr.sin_port = htons(PORT);
    err = bind(ser_sockfd, (struct sockaddr *) &ser_addr, sizeof(ser_addr));
    if (err == -1) {
        LOGD("testtest bind error:%s\n", strerror(errno));
        return -1;
    }

    err = listen(ser_sockfd, 5);
    if (err == -1) {
        LOGD("testtest listen error\n");
        return -1;
    }

    LOGD("testtest listen the port:\n");

    while (1) {
        addlen = sizeof(struct sockaddr);
        cli_sockfd = accept(ser_sockfd, (struct sockaddr *) &cli_addr, &addlen);
        if (cli_sockfd == -1) {
            LOGD("testtest accept error\n");
        }
        setsockopt(cli_sockfd, IPPROTO_TCP, TCP_NODELAY, (void *) &enable, sizeof(enable));
        while (1) {
            LOGD("testtest waiting for client...\n");
            n = recv(cli_sockfd, recvline, 1024, 0);
            if (n < 0) {
                LOGD("testtest recv error\n");
                break;
            } else if (n == 0) {
                if (errno == EINTR)continue;
                LOGD("testtest EOF\n");
                break;
            } else {

                LOGD("testtest recv data length is:%d\n", n);
                fir_sendcmd(recvline, n);
            }
        }
        close(cli_sockfd);
        cli_sockfd = -1;
    }

    close(ser_sockfd);

}

pthread_t id;

typedef void *(__cdecl *start_routine)(void *);

int create_server() {

    if (!pthread_create(&id, NULL, (start_routine) cmd_server, NULL)) {
        printf("succeed!\n");
        return 0;
    } else {
        printf("Fail to Create Thread");
        return -1;
    }

}

int hook_CSocket_Recv(void *handle, char *str, int value) {
    LOGD("----------testtest hook CSocket Recv success-------------");
    LOGD("testtest str1 = %s, value = %d", str, value);
    LOGD("--------------------testtest--------------------------------");
    char *buf;
    int *pi;
    int ret;
    int len;
    ret = _CSocket_Recv(handle, str, value);
    if (ret > 0 && str) {
        len = ret;
        buf = (char *) malloc(len + 4);
        pi = (int *) buf;
        pi[0] = 0; // 收包
        memcpy(buf + 4, str, len);
        if (cli_sockfd != -1) {
            send(cli_sockfd, buf, len + 4, 0);
        }
        free(buf);
    }

    return ret;
}


std::string hook_Json_FastWriter_write(void *handle, Json::Value const &value) {

    LOGD("----------testtest hook hook_Json_FastWriter_write success-------------");
    std::string result = _Json_FastWriter_write(handle, value);
    int len = result.length();

    if (len > 0) {
//        char temp[len];
//        strcpy(temp, result.c_str());
        LOGD("testtest change old result = %s, len = %d", result.c_str(), result.length());
    }
    LOGD("-----------------------testtest-----------------------------");

    char *buf;
    int *pi;

    g_cmdhandle = handle;
    if (len > 0) {
        buf = (char *) malloc(len + 4);
        pi = (int *) buf;
        pi[0] = 1;// 发包
        memcpy(buf + 4, result.c_str(), len);
        std::string ts = rulerep(buf, len + 8);
        if (cli_sockfd != -1) {
            send(cli_sockfd, ts.c_str(), ts.length(), 0);
        }
        free(buf);
        char *pnew = (char *) ts.c_str();
        pnew += 4;
        LOGD("testtest change new result = %s, len = %d",
             (std::string(pnew, ts.length() - 8)).c_str(),
             (std::string(pnew, ts.length() - 8)).length());
        return std::string(pnew, ts.length()-8);
    }

    return result;
}

void hook_thread() {
    LOGD("testtest new Hook success, pid = %d\n", getpid());
    while (1) {
        base = (uint32_t) get_module_base(-1, "libCasino.so");

        if (base == NULL) {
            LOGD("testtest get_module_base= NULL\n");
            //return 0;

        } else {
            break;
        }
        usleep(1000);
    }


    pthread_mutex_init(&mutex, NULL);
    pp point;
    point.x = 200;
    point.y = 200;
    fipo[-1] = point;

    registerInlineHook((base + 0x008BB634 + 1), (uint32_t) hook_Json_FastWriter_write,
                       (uint32_t **) &_Json_FastWriter_write);
    inlineHook(base + 0x008BB634 + 1);

//    registerInlineHook((base + 0x006B6D70 + 1), (uint32_t) hook_CSocket_Send,
//                       (uint32_t **) &_CSocket_Send);
//    inlineHook(base + 0x006B6D70 + 1);

    registerInlineHook((base + 0x006B6DAC + 1), (uint32_t) hook_CSocket_Recv,
                       (uint32_t **) &_CSocket_Recv);
    inlineHook(base + 0x006B6DAC + 1);

    LOGD("testtest after hook");
    create_server();
}

int hook_entry(char *a) {

    if (!pthread_create(&id, NULL, (start_routine) hook_thread, NULL)) {
        printf("succeed!\n");
        return 0;
    } else {
        printf("Fail to Create Thread");
        return -1;
    }
    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    hook_entry(NULL);
    //hook_thread();
    return JNI_VERSION_1_4;

}
