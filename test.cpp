
#include <cstring>
#include <string>
#include <cstdio>
#include <vector>
#include <vector>
#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <random>
#include <pbc/pbc.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <chrono>
#include <NTL/mat_ZZ_p.h>
#include <chrono>
#include <cstring>
#include <string>
#include <cstdio>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
using namespace std;

// 输入：密钥，明文指针，明文长度，输出地址
inline bool chacha20_encrypt(const uint8_t key32[32],const uint8_t* pt, size_t pt_len,std::vector<uint8_t>& out){
    // 生成随机字节
    constexpr size_t NONCE_LEN = 12;
    uint8_t nonce[NONCE_LEN];
    if (RAND_bytes(nonce, (int)NONCE_LEN) != 1) return false;

    // 生成初始向量（counter + nonce）
    uint8_t iv16[16] = {0};
    iv16[0] = 1; // counter=1（小端）
    memcpy(iv16 + 4, nonce, NONCE_LEN);

    // 创建上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // 填充 out
    out.resize(NONCE_LEN + pt_len);
    memcpy(out.data(), nonce, NONCE_LEN);
    uint8_t* ct = out.data() + NONCE_LEN;

    // 初始化上下文
    int len = 0;
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key32, iv16);

    // 加密 输入为上下文ctx，密文地址 ct，明文 pt，明文长度 pt_len
    EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len);

    // 输出
    EVP_EncryptFinal_ex(ctx, ct + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    return 1;
}
// 解密函数
inline bool chacha20_decrypt(
    const uint8_t key32[32],
    const uint8_t* in, size_t in_len,
    vector<uint8_t>& pt_out)
{
    constexpr size_t NONCE_LEN = 12;
    if (in_len < NONCE_LEN) return false;

    const uint8_t* nonce = in;
    const uint8_t* ct = in + NONCE_LEN;
    size_t ct_len = in_len - NONCE_LEN;

    uint8_t iv16[16] = {0};
    iv16[0] = 1; // counter=1
    memcpy(iv16 + 4, nonce, NONCE_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    pt_out.resize(ct_len);
    int len = 0;
    bool ok =
        EVP_DecryptInit_ex(ctx, EVP_chacha20(), nullptr, key32, iv16) == 1 &&
        (ct_len == 0 || EVP_DecryptUpdate(ctx, pt_out.data(), &len, ct, (int)ct_len) == 1) &&
        EVP_DecryptFinal_ex(ctx, pt_out.data() + len, &len) == 1;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) pt_out.clear();
    return ok;
}

pairing_t pairing;
void my_win_random(mpz_t rop, mpz_t upper, void *data) {
    (void)data;  // 不使用，可忽略

    // 如果 upper == 0，直接返回 0，避免除以 0
    if (mpz_sgn(upper) <= 0) {
        mpz_set_ui(rop, 0);
        return;
    }

    // upper 的比特长度，决定我们需要多少字节
    size_t bits   = mpz_sizeinbase(upper, 2);
    size_t nbytes = (bits + 7) / 8;

    BYTE *buf = (BYTE *)malloc(nbytes);
    if (!buf) {
        // 这里简单处理，你也可以改成返回错误码
        fprintf(stderr, "my_win_random: malloc failed\n");
        abort();
    }

    HCRYPTPROV hProv;
    if (!CryptAcquireContext(
            &hProv,
            NULL,
            NULL,
            PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        fprintf(stderr, "my_win_random: CryptAcquireContext failed\n");
        free(buf);
        abort();
            }

    // 使用“拒绝采样”避免偏差：如果随机数 >= upper，就重来一次
    while (1) {
        if (!CryptGenRandom(hProv, (DWORD)nbytes, buf)) {
            fprintf(stderr, "my_win_random: CryptGenRandom failed\n");
            CryptReleaseContext(hProv, 0);
            free(buf);
            abort();
        }

        // 把随机字节导入 rop
        mpz_import(rop, nbytes, 1, 1, 0, 0, buf);

        // 如果 rop < upper，满足要求，跳出循环
        if (mpz_cmp(rop, upper) < 0) {
            break;
        }
        // 否则重新生成一次
    }

    CryptReleaseContext(hProv, 0);
    free(buf);
}

void PairingInit() {
    pbc_random_set_function(my_win_random, NULL);
    // 读取 a.param 参数文件到 param_str
    std::ifstream infile("a.param");
    if (!infile.is_open()) {
        std::cerr << "Cannot open param file\n";
        exit(1);
    }
    std::stringstream buffer;
    buffer << infile.rdbuf();
    std::string param_str = buffer.str();
    infile.close();
    // pbc_param_init_set_str 初始化 pairing
    pbc_param_t param;
    pbc_param_init_set_str(param, param_str.c_str());
    pairing_init_pbc_param(pairing, param);
    pbc_param_clear(param);
}
using namespace grpc;
#include "Service.grpc.pb.h"

unique_ptr<ProtoStruct::ProtoService::Stub>  ClientInit() {
    PairingInit();
    string ip = "127.0.0.1:50051";
    auto channel = CreateChannel(ip, InsecureChannelCredentials());

    // unique_ptr<ProtoStruct::ProtoService::Stub> stub =
    //     ProtoStruct::ProtoService::NewStub(channel);
    return ProtoStruct::ProtoService::NewStub(channel);
}
using namespace std::chrono;
int TestEncypt() {
    auto stub = ClientInit();

    std::string a(256, 'A');                 // 256B，全是 0
    // 或：std::string a(256, 'A');            // 256B，全是 'A'

    ProtoStruct::DataMessage in;
    in.set_data(a.data(), a.size());
    long long time1=0;
    auto t1=steady_clock::now();
    ProtoStruct::CTMessage ct;
    {
        grpc::ClientContext ctx1;
        grpc::Status s1 = stub->EncData(&ctx1, in, &ct);
        if (!s1.ok()) {
            std::cerr << "EncData RPC failed: " << s1.error_message() << "\n";
            return 1;
        }
    }
    auto t2=steady_clock::now();
    time1+=duration_cast<milliseconds>(t2-t1).count();
    cout<< time1<<endl;
    t1 = steady_clock::now();
    ProtoStruct::DataMessage out;
    {
        grpc::ClientContext ctx2;
        grpc::Status s2 = stub->DecData(&ctx2, ct, &out);
        if (!s2.ok()) {
            std::cerr << "DecData RPC failed: " << s2.error_message() << "\n";
            return 1;
        }
    }
    t2=steady_clock::now();
    time1+=duration_cast<milliseconds>(t2-t1).count();

    cout<< time1<<endl;
    cout<<out.data();
}
int TestGetSetKey() {
    auto stub = ClientInit();
    vector<bool> attributeVec1={1,0,0,1,0};
    ProtoStruct::AttributeMessage attributeMessage;
    ProtoStruct::USKMessage uskMessage;
    for (auto i:attributeVec1) {
        attributeMessage.add_attribute(i);
    }

        ClientContext ctx1;
        Status s1 = stub->GetUSK(&ctx1, attributeMessage, &uskMessage);
        if (!s1.ok()) {
            std::cerr << "GetKey RPC failed: " << s1.error_message() << "\n";
            return 1;
        }

        cout<<"Key Get Success!"<<endl;
        ClientContext ctx2;
        ProtoStruct::EmptyMessage emptyMessage;

        Status s2 = stub->SetUSK(&ctx2,uskMessage,&emptyMessage);

    if (!s2.ok()) {
        std::cerr << "SetKey RPC failed: " << s2.error_message() << "\n";
        return 1;
    }else {
        cout<<"SetKey Success!"<<endl;
    }
    return 0;
}
void TestAll() {
    auto stub = ClientInit();
    vector<bool> attributeVec1={1,0,0,1,0};
    ProtoStruct::AttributeMessage attributeMessage;
    ProtoStruct::USKMessage uskMessage;
    for (auto i:attributeVec1) {
        attributeMessage.add_attribute(i);
    }

    ClientContext ctx1;
    Status s1 = stub->GetUSK(&ctx1, attributeMessage, &uskMessage);
    if (!s1.ok()) {
        std::cerr << "GetKey RPC failed: " << s1.error_message() << "\n";
        return ;
    }

    cout<<"Key Get Success!"<<endl;
    ClientContext ctx2;
    ProtoStruct::EmptyMessage emptyMessage;

    Status s2 = stub->SetUSK(&ctx2,uskMessage,&emptyMessage);

    if (!s2.ok()) {
        std::cerr << "SetKey RPC failed: " << s2.error_message() << "\n";
        return ;
    }else {
        cout<<"SetKey Success!"<<endl;
    }

    std::string a(256, 'A');                 // 256B，全是 0
    // 或：std::string a(256, 'A');            // 256B，全是 'A'

    ProtoStruct::DataMessage in;
    in.set_data(a.data(), a.size());
    long long time1=0;
    auto t1=steady_clock::now();
    ProtoStruct::CTMessage ct;
    {
        grpc::ClientContext ctx3;
        grpc::Status s1 = stub->EncData(&ctx3, in, &ct);
        if (!s1.ok()) {
            std::cerr << "EncData RPC failed: " << s1.error_message() << "\n";
            return ;
        }
    }
    auto t2=steady_clock::now();
    time1+=duration_cast<milliseconds>(t2-t1).count();
    cout<< time1<<endl;
    t1 = steady_clock::now();
    ProtoStruct::DataMessage out;
    {
        grpc::ClientContext ctx4;
        grpc::Status s2 = stub->DecData(&ctx4, ct, &out);
        if (!s2.ok()) {
            std::cerr << "DecData RPC failed: " << s2.error_message() << "\n";
            return ;
        }
    }
    t2=steady_clock::now();
    time1+=duration_cast<milliseconds>(t2-t1).count();

    cout<< time1<<endl;
    cout<<out.data();
}
int main() {

    TestAll();
}
