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

void MSHookFunction(void *symbol, void *replace, void **result, int flag) {
    uint32_t page_size = getpagesize();
    char *tp = (char *) mmap(0, 10, PROT_ALL, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char opcode[5] = {0x8b, 0x1c, 0x24, 0x90, 0x90};
    if (tp == NULL) {
        LOGD("testtestMSHookFunction:mmap() fail");
        return;
    }
    uint32_t entry_page_start = ((uint32_t) symbol) & (~(page_size - 1));
    uint32_t jmpback_addr, jmp_addr;
    jmpback_addr = (uint32_t) (((char *) (symbol)) - ((char *) tp) - 5);
    jmp_addr = (uint32_t) (((char *) replace) - ((char *) (symbol)) - 5);
    unsigned char jmp_op = 0xe9;
    unsigned char mov_ebx = 0xbb;
    if (flag) {
        memcpy(tp, symbol, 6);
        //memcpy(tp+1,&opcode,5);
        memcpy(tp + 6, &jmp_op, 1);
        memcpy(tp + 7, &jmpback_addr, 4);
    } else {
        sign += base;
        memcpy(tp, symbol, 4);
        memcpy(tp + 4, &mov_ebx, 1);
        memcpy(tp + 5, &sign, 4);
        memcpy(tp + 9, &jmp_op, 1);
        memcpy(tp + 10, &jmpback_addr, 4);
    }
    mprotect((uint32_t *) entry_page_start, page_size, PROT_EXEC | PROT_READ | PROT_WRITE);
    memcpy(symbol, &jmp_op, 1);
    memcpy((char *) symbol + 1, &jmp_addr, 4);
    mprotect((uint32_t *) entry_page_start, page_size, PROT_EXEC | PROT_READ);
    *(char **) result = tp;
}

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
    if (cli_sockfd != -1) {
        send(cli_sockfd, buf, len + 8, 0);
    }
    free(buf);
    return _SocketHelper_sendMsg(handle, id, pbuf, len);
}


int fake_AES128_CBC_decrypt_buffer(char *out, char *in, int inlen, char *key, int *outlen) {
    LOGD("testtest fake_AES128_CBC_decrypt_buffer out = %s, in =%s, inlen = %d, key = %s, outlen=%d",
         out, in, inlen, key, outlen);
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
    LOGD("testtest execute cmd=%s", cmd);
    int *pi;
    char *pt;

    if (cmd == NULL || cmdlen <= 0) {
        return -1;
    } else {

        pi = (int *) cmd;
        pt = cmd + 4;

        if (!memcmp(cmd, "send", 4))  //发送数据
        {
            // 1 id data = len + 8
            // send id data
            if (g_cmdhandle) {
                LOGD("testtest execute cmd  id= %d, data=%s, len = %d", pi[1], pt + 4, cmdlen - 8);
                _SocketHelper_sendMsg(g_cmdhandle, pi[1], pt + 4, cmdlen - 8);
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

pthread_mutex_t mutex;

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
    srand(time(NULL));

    *(int *) &getBuff = base + 0x0067FC94;

    registerInlineHook((base + 0x0067D648), (uint32_t) fake_SocketHelper_sendMsg,
                       (uint32_t **) &_SocketHelper_sendMsg);
    inlineHook(base + 0x0067D648);

    registerInlineHook((base + 0x00A91BF8), (uint32_t) fake_AES128_CBC_decrypt_buffer,
                       (uint32_t **) &_AES128_CBC_decrypt_buffer);
    inlineHook(base + 0x00A91BF8);

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
