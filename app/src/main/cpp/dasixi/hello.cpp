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
#include "inlineHook.h"
#include<vector>

#define FIFO  "/sdcard/fifo_file"
#define MAXLINE 4048
#define LOG_TAG "DEBUG"
#define PROT_ALL PROT_READ|PROT_WRITE|PROT_EXEC
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
uint32_t base;
uint32_t sign = 0x00573339;

pthread_mutex_t mutex;


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

typedef unsigned short ushort;
typedef unsigned char uchar;
int pos, len;
void *g_cmdhandle = NULL;
void *g_cmdhandle0 = NULL;
int gethandle = 0;

int (*_socket_read_end)(int id);

int (*_socket_write_end)(int id);

int (*_sendcmd)(void *handle, char *cmd, uint32_t cmdlen);

int *(*luaL_newstate)();

int (*socket_get_buffer)(int id, char *buf, int len);

int *(*get_inst)();

int *(*GetPacket)(int *inst, int id, int un);

int (*lua_pcall)(void *L, int nargs, int nresults, int errfunc);

int (*luaL_openlibs)(void *L);

char (*lua_tolstring)(void *L, int idx, size_t *len);

int (*_compress)(void *dest, uint32_t *destLen, void *source, uint32_t sourceLen);


int (*_CrevasseBuffer)(void *handle, uchar *str, ushort len);


int (*_AES128_CBC_decrypt_buffer)(char *out, char *in, int inlen, char *key, int *outlen);


int (*_SocketHelper_sendMsg)(void *handle, int id, char *pbuf, int len);

int (*_TCPSocket_SendMsg)(void *handle, char const *data, int len);

int (*_encryptAES256Lua)(char const *data, int dataLen, char const *key, int keyLen);

int
(*_cryptAES256)(bool bo, uchar *data, int dataLen, uchar *key, int keyLen, uchar *dd, int ddlen);

int
(*_Crypto_cryptAES256)(bool b, uchar *indata, int inlen, uchar *outdata, int outlen,
                       uchar *data, int len);

int (*getBuff)(void *p);

int (*string_cr)(void *p, char *str, int *t);

int (*string_del)(void *p);

int cli_sockfd = -1;
int g_cmd, g_ver, g_gameid;

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

int crypto_encryptAES256Lua(char const *data, int dataLen, char const *key, int keyLen) {
    LOGD("testtest crypto_encryptAES256Lua data=%s, datalen=%d, key=%s, keylen=%d", data,dataLen,key,keyLen);
    int result = _encryptAES256Lua(data, dataLen, key, keyLen);
    return result;
}

//bool,uchar *,int,uchar *,int,uchar *,int
int Crypto_cryptAES256(bool bo, uchar *data, int dataLen, uchar *key, int keyLen, uchar *dd,
                       int ddlen) {
    int result = _cryptAES256(bo, data, dataLen, key, keyLen, dd, ddlen);
    LOGD("testtest Crypto_cryptAES256 bo=%d, data=%s, datalen=%d, key=%s, keylen=%d, dd=%s, ddlen=%d", bo,data, dataLen, key,
         keyLen,dd,ddlen);
    return result;
}

int decdata(uchar *str, int len) {
    if (len <= 18)return 0;
    str += 18;
    len -= 18;
    int i = 0;
    while (i < len) {
        str[i] ^= 0xa1;
        i++;
    }
    return 1;
}

int fake_TCPSocket_SendMsg(void *handle, char const *data, int len) {
    char *buf;
    int *pi;

    g_cmdhandle = handle;
    buf = (char *) malloc(len + 4);
    pi = (int *) buf;
    pi[0] = 1;
    if (len)memcpy(buf + 4, data, len);
//    _encryptAES256Lua(buf,len,mKey,mkeyLen);
    if (cli_sockfd != -1) {
        send(cli_sockfd, buf, len + 4, 0);
    }

    LOGD("testtest fake_TCPSocket_SendMsg data =%s, len=%d", buf, len);
    free(buf);
    return _TCPSocket_SendMsg(handle, data, len);
}

int fake_SocketHelper_sendMsg(void *handle, int id, char *pbuf, int len) {
    LOGD("testtest fake_SocketHelper_sendMsg id = %d, data = %s, len =%d", id, pbuf, len);
    char *buf, *p;
    int *pi;
    p = pbuf;
    g_cmdhandle = handle;
    buf = (char *) malloc(len + 8);
    pi = (int *) buf;
    pi[0] = 1;
    pi[1] = id;
    if (len)memcpy(buf + 8, p, len);
    std::string ts = rulerep(buf, len + 8);
    if (cli_sockfd != -1) {
        send(cli_sockfd, ts.c_str(), ts.length(), 0);
    }
    free(buf);

    char *pnew = (char *) ts.c_str();
    pnew += 8;
    return _SocketHelper_sendMsg(handle, id, pnew, len - 8);
}


int fake_AES128_CBC_decrypt_buffer(char *out, char *in, int inlen, char *key, int *outlen) {
    if (inlen > 1000) {
        return _AES128_CBC_decrypt_buffer(out, in, inlen, key, outlen);
    }

    char *buf;
    int *pi;
    int result = _AES128_CBC_decrypt_buffer(out, in, inlen, key, outlen);
    int len = inlen;
    buf = (char *) malloc(len + 4);
    pi = (int *) buf;
    pi[0] = 0;
    memcpy(buf + 4, out, len);
    if (cli_sockfd != -1) {
        send(cli_sockfd, buf, len + 4, 0);
    }
    free(buf);

    return result;
}


int fir_sendcmd(char *cmd, int cmdlen) {
    char *pt;

    if (cmd == NULL || cmdlen <= 0) {
        return -1;
    } else {
        cmdlen = cmdlen - 4;
        pt = cmd + 4;

        if (!memcmp(cmd, "send", 4))  //发送数据
        {
            if (g_cmdhandle) {
                decdata((uchar *) pt, cmdlen);
                LOGD("testtest execute cmd data=%s, len = %d", pt, cmdlen);
                if (g_cmdhandle)_TCPSocket_SendMsg(g_cmdhandle, pt, cmdlen);
            }
        }
        if (!memcmp(cmd, "rule", 4))  //添加规则
        {
            rule.push_back(std::string(cmd + 4, cmdlen));

        }
        if (!memcmp(cmd, "dule", 4))  //清空规则
        {
            rule.clear();

        }

    }

    return 0;

}

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
        LOGD("testtestsocket error:%s\n", strerror(errno));
        return -1;
    }

    bzero(&ser_addr, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ser_addr.sin_port = htons(PORT);
    err = bind(ser_sockfd, (struct sockaddr *) &ser_addr, sizeof(ser_addr));
    if (err == -1) {
        LOGD("testtestbind error:%s\n", strerror(errno));
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
            LOGD("testtestaccept error\n");
        }
        setsockopt(cli_sockfd, IPPROTO_TCP, TCP_NODELAY, (void *) &enable, sizeof(enable));
        while (1) {
            LOGD("testtestwaiting for client...\n");
            n = recv(cli_sockfd, recvline, 1024, 0);
            if (n < 0) {
                LOGD("testtestrecv error\n");
                break;
            } else if (n == 0) {
                if (errno == EINTR)continue;
                LOGD("testtestEOF\n");
                break;
            } else {

                LOGD("testtestrecv data length is:%d\n", n);
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
        LOGD("testtest create_server success");
        return 0;
    } else {
        LOGD("testtest Fail to Create Thread");
        return -1;
    }

}


void hook_thread() {
    LOGD("testtest Hook success, pid = %d\n", getpid());
    while (1) {
        base = (uint32_t) get_module_base(-1, "libPuke.so");
        if (base == NULL) {
        } else {
            break;
        }
        usleep(1000);
    }
    pthread_mutex_init(&mutex, NULL);

    //cocos2d::extra::Crypto::encryptAES256Lua(char const*,int,char const*,int)	00A8C8F8
    registerInlineHook((base + 0x00A8C8F8), (uint32_t) crypto_encryptAES256Lua,
                       (uint32_t **) &_encryptAES256Lua);
    inlineHook(base + 0x00A8C8F8);

    //cocos2d::extra::Crypto::cryptAES256(bool,uchar *,int,uchar *,int,uchar *,int)	00A8FB98
    registerInlineHook((base + 0x00A8FB98), (uint32_t) Crypto_cryptAES256,
                       (uint32_t **) &_cryptAES256);
    inlineHook(base + 0x00A8FB98);




//    registerInlineHook((base + 0x0067FB30), (uint32_t) fake_TCPSocket_SendMsg,
//                       (uint32_t **) &_TCPSocket_SendMsg);
//    inlineHook(base + 0x0067FB30);

//    registerInlineHook((base + 0x0067D648), (uint32_t) fake_SocketHelper_sendMsg,
//                       (uint32_t **) &_SocketHelper_sendMsg);
//    inlineHook(base + 0x0067D648);

//    registerInlineHook((base + 0x00A91BF8), (uint32_t) fake_AES128_CBC_decrypt_buffer,
//                       (uint32_t **) &_AES128_CBC_decrypt_buffer);
//    inlineHook(base + 0x00A91BF8);

//    registerInlineHook((base + 0x00A8FB98), (uint32_t) fake_Crypto_cryptAES256
//                       (uint32_t **) &_Crypto_cryptAES256);
//    inlineHook(base + 0x00A8FB98);

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
