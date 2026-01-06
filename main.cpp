#include <iostream>
#include <fstream>
#include <sstream>
#include "pbc.h"
#include <ctime>
#include <random>
#include <pbc.h>
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
using namespace std;
using namespace NTL;
using namespace std::chrono;
// 基于 Windows CryptoAPI 的安全随机数生成：0 <= rop < upper
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
struct USK {
    element_t K;
    element_t L;
    vector<element_t*> sk;
    vector<bool> attribute;
    USK(int AttributeNum,pairing_t pairings) {
        element_init_G1(K,pairings);
        element_init_G1(L,pairings);
        sk.resize(AttributeNum);
        attribute.resize(AttributeNum);

    }
    ~USK() {
        element_clear(K);
        element_clear(L);
        for (auto p:sk) {
            if (p) {
                element_clear(*p);
                free(p);
            }
        }

    }
};
struct CT {
    element_t C;
    element_t CC;
    vector<element_t*> Cs;
    vector<element_t*> Ds;
    CT(pairing_t pairings) {
        element_init_GT(C,pairings);
        element_init_G1(CC,pairings);
    }
    ~CT() {
        element_clear(C);
        element_clear(CC);
        for (int i=0; i<Cs.size(); i++) {
            element_clear(*Cs[i]);
        }
        for (int i=0; i<Ds.size(); i++) {
            element_clear(*Ds[i]);
        }
    }
};
class CPABE {
//  公共参数初始化
public:
    pairing_t pairing;
    element_t g;
    element_t ga;
    vector<element_t*> h;
    element_t alpha;
    element_t msk;
    element_t talpha;
    int u;

//  公共函数
public:
    void setup(int U) {
        // 替换全局 u
        u=U;
        // 随机数源改变
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
        // 初始化生成元 g
        element_init_G1(g,pairing);
        element_random(g);
        // 初始化 U 个随机元素;
        for (int i=0;i<=U-1;i++) {
            element_t* temp=(element_t*)malloc(sizeof(element_t));
            element_init_G1(*temp,pairing);
            element_random(*temp);
            h.push_back(temp);
        }
        // 初始化 g^a
        element_t a;
        element_init_Zr(a,pairing);
        element_random(a);
        element_init_G1(ga,pairing);
        element_mul_zn(ga,g,a);
        // 初始化 alpha,galpha
        element_init_Zr(alpha,pairing);
        element_random(alpha);
        // e(g,g)^{\alpha}
        element_init_GT(talpha,pairing);
        element_pairing(talpha,g,g);
        element_mul_zn(talpha,talpha,alpha);
        // 初始化 msk
        element_init_G1(msk,pairing);
        element_mul_zn(msk,g,alpha);

    }
    // 函数作用：生成用户私钥。
    // 输入：一个布尔向量，0位置为 true 代表拥有 0 属性。
    // 输出：私钥结构体。
    // 问题点：没有属性的位置是空指针，访问就会报错。需要在使用私钥前进行判断其是否访问的空指针。
    USK GenKey(vector<bool> attribute) {
        // 初始化化 KEY 结构体
        int AttributeNum=attribute.size();
        USK RSK=USK(AttributeNum,pairing);
        // 检测是否为合法 s

        // 定义变量
        element_t t;
        // 变量初始化
        element_init_Zr(t,pairing);

        // 选取随机数 t
        element_random(t);
        // K=g^alpha * g^{at}
        element_mul_zn(RSK.K,ga,t);
        element_mul(RSK.K,RSK.K,msk);
        // L=g^t
        element_mul_zn(RSK.L,g,t);
        // SK_x=h_x^t
        for (int i=0;i<=AttributeNum-1;i++) {
            if (attribute[i]) {
                element_t* temp=(element_t*)malloc(sizeof(element_t));
                element_init_G1(*temp,pairing);
                element_mul_zn(*temp,*h[i],t);
                RSK.sk[i]=temp;
            }
        }
        // vector 可以等于号 = 赋值
        RSK.attribute=attribute;
        return RSK;
    }
    void GenMatrix() {

    }

    CT Encryt(element_t message,vector<vector<element_t*>> M, vector<int> Rho) {
        // 统计矩阵 M 的行列数 n x l;
        int l = M.size();
        int n = M[0].size();
        if (l!=Rho.size()) {
            cout<<"Rho Function Size Error!"<<endl;// 输入的 Rho 数组大小与 M 矩阵的行数不一致则报错。
        }
        // 初始化密文结构体
        CT ct=CT(pairing);
        // 生成随机向量 v = (s,y2,...,yn)
        vector<element_t*> v;
        element_t s;
        element_init_Zr(s,pairing);
        element_random(s);
        v.push_back(&s);

        for (int i=0; i<=n-2; i++) { // 前面生成了一个元素 s，此处生成 n-1 个元素即可。
            element_t* y=(element_t*)malloc(sizeof(element_t));
            element_init_Zr(*y,pairing);
            element_random(*y);
            v.push_back(y);
        }

        // C = message * e(g,g)^{\alpha s}
        element_t right;
        element_init_GT(right,pairing);
        element_pow_zn(right,talpha,s);
        element_mul(ct.C,right,message);
        // C' = g^s
        element_init_G1(ct.CC,pairing);
        element_mul_zn(ct.CC,g,s);

        // Compute CD

        // lambdaMul 用于存储向量乘法运算的中间结果，lambdaAdd 用于存储向量乘法运算的中间结果的和。
        element_t lambdaMul,lambdaAdd;
        element_init_Zr(lambdaMul,pairing);
        element_init_Zr(lambdaAdd,pairing);
        element_t CRight,r,nr;
        element_init_Zr(r,pairing);
        element_init_Zr(nr,pairing);
        element_init_G1(CRight,pairing);
        for (int i=0; i<=l-1; i++) {
            // λ_i = v * M_i
            element_set0(lambdaAdd);
            for (int j=0; j<=n-1; j++) {
                element_mul(lambdaMul,*v[j],*M[i][j]);
                element_add(lambdaAdd,lambdaAdd,lambdaMul);
            }
            // 初始化 C_i,D_i
            element_t* Ci=(element_t*)malloc(sizeof(element_t));
            element_init_G1(*Ci,pairing);
            element_t* Di=(element_t*)malloc(sizeof(element_t));
            element_init_G1(*Di,pairing);
            // C_i = g^{a*lambda}h[rho[i]]^{-ri}

            element_random(r);
            element_neg(nr,r);
            element_mul_zn(*Ci,ga,lambdaAdd);
            element_mul_zn(CRight,*h[Rho[i]],nr);
            element_mul(*Ci,*Ci,CRight);
            ct.Cs.push_back(Ci);
            // D_i = g^{ri}
            element_mul_zn(*Di,g,r);
            ct.Ds.push_back(Di);
        }
        // 数组不能单独返回，但是如果数组是结构体内的就可以单独返回。结构体会对数组进行按值拷贝。
        return ct;
    }
    // 解密函数
    // Input：密文结构体 CT / 私钥结构体 USK
    // Output：明文 M
    element_t* Decryt(CT& ct,USK& sk,const vector<vector<element_t*>>& M, const vector<int>& Rho) {
        // l 行 n 列
        int l = M.size();
        int n = M[0].size();
        if (l!=Rho.size()) {
            cout<<"Rho Function Size Error!"<<endl;// 输入的 Rho 数组大小与 M 矩阵的行数不一致则报错。
        }
        // 计算 i \in I 与 M_I
        // 此处 NeededRow 存储的是行号。
        vector<int> NeededRow;
        vector<vector<element_t*>> MI;
        vector<int> Index; // 存储原矩阵 M 行号到 MI 行号的映射。
        Index.resize(l);
        int row=0;
        for (int i=0; i<=l-1; i++) {
            if (sk.attribute[Rho[i]]) {
                NeededRow.push_back(i);
                MI.push_back(M[i]);
                Index[i]=row;
                row++;
            }
        }

        // 求 ω
        vector<element_t*> w = GetSolve(MI);
        // left = e (CC,K)
        element_t left;
        element_init_GT(left,pairing);
        element_pairing(left,ct.CC,sk.K);
        // right = \prod e(C_i,L)e(D(i),Ki)
        element_t RL,RR;
        element_init_GT(RL,pairing);
        element_init_GT(RR,pairing);
        element_t* Right=(element_t*)malloc(sizeof(element_t));
        element_init_GT(*Right,pairing);
        element_set1(*Right);
        for (auto i : NeededRow) {
            element_pairing(RL,*ct.Cs[i],sk.L);
            element_pairing(RR,*ct.Ds[i],*sk.sk[Rho[i]]);
            element_mul(RR,RL,RR);
            element_pow_zn(RR,RR,*w[Index[i]]);
            element_mul(*Right,RR,*Right);
        }
        // 计算 Right = e (CC,K) / \prod e(C_i,L)e(D(i),Ki) = e(g,g)^{\alpha s}
        element_div(*Right,left,*Right);
        // 计算 M = ct.C / Right
        element_div(*Right,ct.C,*Right);
        return Right;
    }
    vector<element_t*> GetSolve(vector<vector<element_t*>> M ) {
        // 初始化模数

        ZZ mod=conv<ZZ>("730750818665451621361119245571504901405976559617");
        ZZ_p::init(mod);

        // 初始化 NTL 矩阵
        int l=M.size();
        int n=M[0].size();
        Mat<ZZ_p> MP;
        MP.SetDims(n,l+1);

        // 初始化 mpz 元素 t
        mpz_t t;
        mpz_init(t);

        // PBC 元素转 NTL 元素
        for (int i=0;i<=l-1;i++) {
            for (int j=0;j<=n-1;j++) {
                element_to_mpz(t,*M[i][j]);
                char* tt=mpz_get_str(nullptr, 10, t);
                MP[j][i]=conv<ZZ_p>(tt);
                free(tt);
            }
        }

        ZZ_p a1,a2;
        a1=conv<ZZ_p>(1);
        a2=conv<ZZ_p>(0);
        MP[0][l]=a1;
        for (int i=1;i<=n-1;i++) {
            MP[i][l]=a2;
        }
        mpz_clear(t);
        gauss(MP);

        // 高斯消元法得到矩阵特解

        Vec<ZZ_p> omega;
        omega.SetLength(l);
        clear(omega);              // 自由变量默认=0

        for (int i = 0; i < n; i++) {
            int lead = -1;
            for (int j = 0; j < l; j++) {
                if (!IsZero(MP[i][j])) { lead = j; break; }
            }

            if (lead == -1) {
                // 0 ... 0 | c
                if (!IsZero(MP[i][l])) {
                    // 无解：Aω=b 不可满足
                    cout<<"Error: No Solution Equation!"<<endl;
                }
                continue;
            }

            // 主元变量 = 右侧常数项（因为自由变量我们设0）
            omega[lead] = MP[i][l];
        }
        vector<element_t*> result;
        result.resize(l);

        for (int j = 0; j < l; ++j) {
            // 初始化元素
            element_t *tempElement = (element_t *) malloc(sizeof(element_t));
            element_init_Zr(*tempElement, pairing);
            // ZZ_p - > ZZ -> mpz_t -> element_t
            ZZ zj = rep(omega[j]);
            long num = NumBytes(zj);
            unsigned char *bytes = new unsigned char[num];


            BytesFromZZ(bytes, zj, num);
            mpz_t tmp;
            mpz_init(tmp);
            mpz_import(tmp, num, -1, 1, 1, 0, bytes);
            element_set_mpz(*tempElement, tmp);
            result[j] = tempElement;
            mpz_clear(tmp);
        }

        return result;
}
    // 测试 element_cmp 的子函数。测试目的为验证 PBC 库中 G1 群元素的加法和乘法是否一样。
    void test2() {
        element_t a,b,c,d;
        element_init_G1(a,pairing);
        element_init_G1(b,pairing);
        element_init_G1(c,pairing);
        element_init_G1(d,pairing);
        element_random(a);
        element_random(b);
        element_set(c,a);
        element_set(d,b);
        element_mul(a,a,b);
        element_add(c,c,d);
        cout<<element_cmp(a,c)<<endl;
    }
};
// 单一属性解密测试。
void TestEnc() {
    CPABE abe;
    // 五个属性， 0 1 2 3 4
    abe.setup(5);
    // 生成私钥
    vector<bool> attributeVec={1,0,0,0,0};
    USK usk = abe.GenKey(attributeVec);
    // 构造明文 message
    element_t message;
    element_init_GT(message,abe.pairing);
    element_random(message);
    // 构造控制矩阵 M
    vector<vector<element_t*>> M;
    element_t *temp=(element_t*)malloc(sizeof(element_t));
    element_init_Zr(*temp,abe.pairing);
    element_set1(*temp);
    M.resize(1);
    M[0].push_back(temp);
    // 测试加密：对属性 0 进行加密。
    vector<int> Rho={0};
    CT ct=abe.Encryt(message,M,Rho);
    // 解密
    element_t *a=abe.Decryt(ct,usk,M,Rho);
    cout << element_cmp(*a, message) << endl;
}
// 多属性解密测试
// 五个属性， 0 1 2 3 4
// 0 - 工厂 A
// 1 - 工厂 B
// 2 - 工厂 C
// 3 - 经理
// 4 - 员工
// 测试生成密文只有 A 工厂 和 B工厂的经理可以解密
// 控制矩阵为 [1,0] [0,-1][1,0][0,-1]
void TestEnc2() {
    CPABE abe;
    long long time1=0,time2=0;
    abe.setup(5);
    // 生成三个私钥 ABC 工厂对应的经理
    vector<bool> attributeVec1={1,0,0,1,0};
    vector<bool> attributeVec2={0,1,0,1,0};
    vector<bool> attributeVec3={0,0,1,1,0};
    USK usk1 = abe.GenKey(attributeVec1);
    USK usk2 = abe.GenKey(attributeVec2);
    USK usk3 = abe.GenKey(attributeVec3);
    // 构造明文 message
    element_t message;
    element_init_GT(message,abe.pairing);
    element_random(message);
    // 构造控制矩阵 M
    vector<vector<element_t*>> M;
    element_t *temp=(element_t*)malloc(sizeof(element_t));
    element_init_Zr(*temp,abe.pairing);

    M.resize(4);
    element_set1(*temp);
    M[0].push_back(temp);
    temp=(element_t*)malloc(sizeof(element_t));
    element_init_Zr(*temp,abe.pairing);
    element_set0(*temp);
    M[0].push_back(temp);

    temp=(element_t*)malloc(sizeof(element_t));
    element_init_Zr(*temp,abe.pairing);
    M[1].push_back(temp);
    temp=(element_t*)malloc(sizeof(element_t));
    element_init_Zr(*temp,abe.pairing);
    element_set1(*temp);
    element_neg(*temp,*temp);
    M[1].push_back(temp);

    temp=(element_t*)malloc(sizeof(element_t));
    element_init_Zr(*temp,abe.pairing);
    element_set1(*temp);
    M[2].push_back(temp);
    temp=(element_t*)malloc(sizeof(element_t));
    element_init_Zr(*temp,abe.pairing);
    element_set0(*temp);
    M[2].push_back(temp);

    temp=(element_t*)malloc(sizeof(element_t));
    element_init_Zr(*temp,abe.pairing);
    M[3].push_back(temp);
    temp=(element_t*)malloc(sizeof(element_t));
    element_init_Zr(*temp,abe.pairing);
    element_set1(*temp);
    element_neg(*temp,*temp);
    M[3].push_back(temp);
    // 测试加密：对属性 0 进行加密。
    vector<int> Rho={0,3,1,3};
    auto t1=steady_clock::now();
    CT ct=abe.Encryt(message,M,Rho);
    auto t2=steady_clock::now();
    time1+=duration_cast<milliseconds>(t2-t1).count();

    cout<<time1<<endl;

    // 解密
    auto t3=steady_clock::now();
    element_t *a1=abe.Decryt(ct,usk1,M,Rho);
    auto t4=steady_clock::now();
    time2+=duration_cast<milliseconds>(t4-t3).count();
    cout<<time2<<endl;
    element_t *a2=abe.Decryt(ct,usk2,M,Rho);

    element_t *a3=abe.Decryt(ct,usk3,M,Rho);

}
// 测试 G1 群元素加法和乘法一致性的主函数。和实现 ABE 无关。

#include <chrono>
using Clock = std::chrono::steady_clock;



void TestADD() {
    CPABE abe;
    abe.setup(5);
    abe.test2();
}
int main() {
    TestEnc2();
    std::cout << "Hello, World!" << std::endl;
    return 0;
}