#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>

/* 右移运算Right shift */
#define RTSHIFT(x,n)		( (x)>>(n) )
/* 循环右移Right rotate */
#define RTROT(xsize,x,n)	( ((x)>>(n)) | ( ((x)&((1<<(n+1))-1)) << ( ((xsize)<<3)-(n) )) )

#define RTROT512(xsize,x,n)	( ((x)>>(n)) | ( ((x)&(((uint64_t)1<<(n+1))-1)) << ( ((xsize)<<3)-(n) )) )

static uint32_t hv_primes[8]= { 
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};
/* Variable hash values: 哈希值变量　*/
uint32_t hv[8];

/* kv_primes[64]　　从前６４个素数的立方根中提取的kv初始值 round constants */
const uint32_t kv_primes[64]= {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
/* Variable round constants kv[64] kV变量　*/
uint32_t kv[64];


void printHex(const uint8_t *ptr, int len) { // byte length

    for (int i = 0; i < len; ++i) {
        printf("%.2X ", *ptr++);
    }
    printf("\n");
}

int sha256(unsigned char *message) {

    // unsigned char *message = input;
	uint8_t chunk_data[512/8]={0}; 	/* 512bits信息块 */
	unsigned int nch;		/* 信息块总数　Total number of 512bits_chunks */
	unsigned int mod;		/* 信息长度关于512的余数　Result of mod calculation: msgbitlen%512 */
 
	uint32_t words[64]={0};  	/* 运算字单元　32*64 = 2048 bits */
	unsigned long len;		/* length in bytes */
	unsigned long bitlen;		/* length in bits */
	unsigned char digest[8*8+1]={0}; /* convert u32 hv[0-7] to string by sprintf(%08x) */
 
    /* SHA compression vars　运算变量 */
	uint32_t a,b,c,d,e,f,g,h;
	uint32_t s0, s1, ch, temp1, temp2, maj;
 

    /*数据预处理部分*/
    len = strlen((char*)message);
    bitlen = strlen((char*)message) * 8; 

    mod = bitlen % 512;
    nch = (mod >= 448) ? bitlen/512 + 2 : bitlen/512 + 1;

    int k = 448 - (bitlen + 1) % 512;
    if (k < 0) k += 512; // k 不可能等于0，引入输入的bitlen是8的整数倍，不可能是447

    uint32_t new_bitlen = bitlen + 1 + k + 64;
    unsigned char *input = (unsigned char *)calloc(new_bitlen/8, sizeof(unsigned char));
    memcpy(input, message, len);
    // 填充一个1，不能填充一个bit，而是直接填充一个byte，填充的是8位的 (1000 0000)_2
    input[len] = 0x80;

    for (int i = 0; i < k/8; ++i) {
        input[len + 1 + i] = 0x00;
    }
    // 最后64位(8字节)用来存储输入消息的长度
    for (int i = 0; i < sizeof(bitlen); ++i) {
        input[new_bitlen / 8 - 1 - i] = (bitlen >> (8*i))&0xff;
    }
    // printHex(input, 64);
    /*初始化向量*/
    for (int i = 0; i < 8; ++i) 
        hv[i] = hv_primes[i];
    
    for (int i = 0; i < 64; ++i) 
        kv[i] = kv_primes[i];

    /*处理每个数据块*/ 
    for (int nk = 0; nk < nch; ++nk) {
        bzero((void *)chunk_data, sizeof(chunk_data));
        memcpy((void*)chunk_data, input+(nk*64), 64); // 每次copy64 bytes(512 bits)到待处理的内存中
        /* 5. 生成运算字单元  words[64] */
        /* 5.1 words[0]~[15]:  u8 chunck_data[64] ---> u32 words[64] */
        for (int i=0; i<16; i++) {
            words[i]=(chunk_data[4*i]<<24) +(chunk_data[4*i+1]<<16)+(chunk_data[4*i+2]<<8)+chunk_data[4*i+3];
        }
        // printHex(chunk_data, 64);
        // printHex(words, 64);
        /* 5.2 words[15]~[63]: 48 more words */
        for (int i=16; i<64; i++) {
            /* s0 = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3) */
            s0=RTROT(4,words[i-15],7) ^ RTROT(4,words[i-15],18) ^ RTSHIFT(words[i-15],3);
            /* s1 = (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10) */
            s1=RTROT(4,words[i-2],17) ^ RTROT(4,words[i-2],19) ^ RTSHIFT(words[i-2],10);
            /* w[i] = w[i-16] + s0 + w[i-7] + s1 */
            words[i]=words[i-16]+s0+words[i-7]+s1;
        }
        /* 6. 进行64轮的哈希计算　SHA Compression, 64 rounds. */
        /* 更新 a,b,c,d,e,f,g,h */
        a=hv[0]; b=hv[1]; c=hv[2]; d=hv[3]; e=hv[4]; f=hv[5]; g=hv[6]; h=hv[7];
        /* Compress for 64 rounds */
        for (int i=0; i<64; i++) {
            /* S1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25) */
            s1=RTROT(4,e,6)^RTROT(4,e,11)^RTROT(4,e,25);
            /* ch = (e and f) xor ((not e) and g) */
            ch= (e&f)^((~e)&g);
            /* temp1 = h + S1 + ch + kv[i] + w[i] */
            temp1=h+s1+ch+kv[i]+words[i];
            /* S0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22) */
            s0=RTROT(4,a,2)^RTROT(4,a,13)^RTROT(4,a,22);
            /* maj = (a and b) xor (a and c) xor (b and c) */
            maj=(a&b)^(a&c)^(b&c);
            /* temp2 = S0 + maj */
            temp2=s0+maj;
    
            h=g;
            g=f;
            f=e;
            e=d+temp1;
            d=c;
            c=b;
            b=a;
            a=temp1+temp2;
        }    
        /* 7. 修改哈希变量　Modify final values */
        hv[0] += a;
        hv[1] += b;
        hv[2] += c;
        hv[3] += d;
        hv[4] += e;
        hv[5] += f;
        hv[6] += g;
        hv[7] += h;
    }

	/* 8. 生成最终的哈希消息摘要　Generate final hash digest */
	for(int i=0; i<8; i++)
		sprintf((char *)digest+8*i,"%08x",hv[i]); /*Convert to string */

	printf("%s\n", digest);
    return 0;
}


/* initial hash value H for SHA-512 */
static const uint64_t hv_primes512[8] = {
	0x6a09e667f3bcc908ULL,
	0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL,
	0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL,
	0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL,
	0x5be0cd19137e2179ULL
};
/* Variable round constants kv[64] kV变量　*/
uint64_t hv512[8];

/* Hash constant words K for SHA-384 and SHA-512: */
static const uint64_t kv_primes512[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};
/* Variable round constants kv[64] kV变量　*/
uint64_t kv512[80];


int sha512(unsigned char* message) {
     // unsigned char *message = input;
	uint8_t chunk_data[1024/8]={0}; 	/* 1024bits信息块 */
	unsigned long nch;		/* 信息块总数　Total number of 1024 bits_chunks */
	unsigned long mod;		/* 信息长度关于1024的余数　Result of mod calculation: msgbitlen%512 */
 
	uint64_t words[80]={0};  	/* 运算字单元　 64*80 = 5120 bits */
	uint64_t len;		/* length in bytes */
	uint64_t bitlen;		/* length in bits */
	unsigned char digest[8*8*2+1]={0}; /* convert u64 hv[0-7] to string by sprintf(%08x) */
 
    /* SHA compression vars　运算变量 */
	uint64_t a,b,c,d,e,f,g,h;
	uint64_t s0, s1, ch, temp1, temp2, maj;


    /*数据预处理部分*/
    len = strlen((char*)message);
    bitlen = strlen((char*)message) * 8; 

    mod = bitlen % 1024;
    nch = (mod >= 896) ? bitlen/1024 + 2 : bitlen/1024 + 1;

    uint64_t k = 896 - (bitlen + 1) % 1024;
    if (k < 0) k += 1024; // k 不可能等于0，引入输入的bitlen是8的整数倍，不可能是447

    uint64_t new_bitlen = bitlen + 1 + k + 128;
    unsigned char *input = (unsigned char *)calloc(new_bitlen/8, sizeof(unsigned char));
    memcpy(input, message, len);
    // 填充一个1，不能填充一个bit，而是直接填充一个byte，填充的是8位的 (1000 0000)_2
    input[len] = 0x80;

    for (int i = 0; i < k/8; ++i) {
        input[len + 1 + i] = 0x00;
    }
    // 最后128位(16字节)用来存储输入消息的长度
    for (int i = 0; i < sizeof(bitlen); ++i) {  /*这里只支持2^64位数据，理论上应该支持2^128 bits数据*/
        input[new_bitlen / 8 - 1 - i] = (bitlen >> (8*i))&0xff;
    }
    // printHex(input, 128);

    /*初始化向量*/
    for (int i = 0; i < 8; ++i) 
        hv512[i] = hv_primes512[i];
    
    for (int i = 0; i < 80; ++i) 
        kv512[i] = kv_primes512[i];

 /*处理每个数据块*/ 
    for (int nk = 0; nk < nch; ++nk) {
        bzero((void *)chunk_data, sizeof(chunk_data));
        memcpy((void*)chunk_data, input+(nk*128), 128); // 每次copy 128 bytes(1024 bits)到待处理的内存中
        /* 5. 生成运算字单元  words[64] */
        /* 5.1 words[0]~[15]:  u8 chunck_data[128] ---> u64 words[64] */
        for (int i=0; i<16; i++) {
            // words[i]=(chunk_data[4*i]<<24) +(chunk_data[4*i+1]<<16)+(chunk_data[4*i+2]<<8)+chunk_data[4*i+3];
             words[i] = ((uint64_t)chunk_data[8*i]<<56) + ((uint64_t)chunk_data[8*i+1]<<48) +((uint64_t)chunk_data[8*i+2]<<40) + ((uint64_t)chunk_data[8*i+3]<<32) +
                        ((uint64_t)chunk_data[8*i+4]<<24) + ((uint64_t)chunk_data[8*i+5]<<16) +((uint64_t)chunk_data[8*i+6]<<8) +((uint64_t)chunk_data[8*i+7]);
        }
        // printHex(chunk_data, 128);
        // printHex(words, 128);
        /* 5.2 words[15]~[80]: xx more words */
        for (int i=16; i<80; i++) {
            s0=RTROT512(8,words[i-15],1) ^ RTROT512(8,words[i-15],8) ^ RTSHIFT(words[i-15],7);
            /* s1 = (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10) */
            s1=RTROT512(8,words[i-2],19) ^ RTROT512(8,words[i-2],61) ^ RTSHIFT(words[i-2],6);
            /* w[i] = w[i-16] + s0 + w[i-7] + s1 */
            words[i]=words[i-16]+s0+words[i-7]+s1;
        }
        /* 6. 进行64轮的哈希计算　SHA Compression, 64 rounds. */
        /* 更新 a,b,c,d,e,f,g,h */
        a=hv512[0]; b=hv512[1]; c=hv512[2]; d=hv512[3]; e=hv512[4]; f=hv512[5]; g=hv512[6]; h=hv512[7];
        /* Compress for 64 rounds */
        for (int i=0; i<80; i++) {
            /* S1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25) */
            s1=RTROT512(8,e,14)^RTROT512(8,e,18)^RTROT512(8,e,41);
            /* ch = (e and f) xor ((not e) and g) */
            ch= (e&f)^((~e)&g);
            /* temp1 = h + S1 + ch + kv[i] + w[i] */
            temp1=h+s1+ch+kv512[i]+words[i];
            /* S0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22) */
            s0=RTROT512(8,a,28)^RTROT512(8,a,34)^RTROT512(8,a,39);
            /* maj = (a and b) xor (a and c) xor (b and c) */
            maj=(a&b)^(a&c)^(b&c);
            /* temp2 = S0 + maj */
            temp2=s0+maj;
    
            h=g;
            g=f;
            f=e;
            e=d+temp1;
            d=c;
            c=b;
            b=a;
            a=temp1+temp2;
        }    
        /* 7. 修改哈希变量　Modify final values */
        hv512[0] += a;
        hv512[1] += b;
        hv512[2] += c;
        hv512[3] += d;
        hv512[4] += e;
        hv512[5] += f;
        hv512[6] += g;
        hv512[7] += h;
    }

	/* 8. 生成最终的哈希消息摘要　Generate final hash digest */
	// for(int i=0; i<8; i++)
	// 	sprintf((char *)digest+8*i*2,"%08llx",hv512[i]); /*Convert to string */
    for (int i = 0; i < 8; ++i) 
        sprintf((char*)digest + 8*i*2 , "%016llx", hv512[i]);


	printf("%s\n", digest);
    return 0;

}

int main(int argc, char **argv) {

    // sha256((unsigned char *)argv[1]); // type == 256 or 512
    // sha512((unsigned char *)argv[1]); 
    // return 0;

    FILE *fp;
    unsigned char *buffer;
    long file_size;

    char*  inputFileName = argv[2];
    fp = fopen(inputFileName, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file.\n");
        exit(1);
    }

    fseek(fp, 0L, SEEK_END);  // 移动文件指针到文件末尾
    file_size = ftell(fp);    // 获取文件大小
    rewind(fp);               // 重置文件指针到文件开头

    buffer = (unsigned char*) malloc(file_size);  // 分配缓冲区内存
    if (buffer == NULL) {
        fprintf(stderr, "Error allocating memory.\n");
        exit(1);
    }

    fread(buffer, file_size, 1, fp);  // 读取文件内容到缓冲区

    fclose(fp);  // 关闭文件

    // 使用缓冲区中的内容
    // sha256((unsigned char*)buffer);
    // printf("%s", argv[1]);
    clock_t startTime, endTime;
    startTime = clock();
    uint32_t type = atoi(argv[1]);
    if (256 == type) sha256((unsigned char*)buffer);
    else if (512 == type)    sha512((unsigned char*)buffer);
    else printf("only support SHA256 , SHA512");
    endTime = clock();

     printf("Time cost of SHA-%d Encrypt: %f s", type, ((double)endTime - startTime) / CLOCKS_PER_SEC);


    free(buffer);  // 释放缓冲区内存

    return 0;
}
