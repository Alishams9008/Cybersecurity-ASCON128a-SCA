#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    uint64_t x0, x1, x2, x3, x4;
} state_t;

#define RATE 8
#define IV 0x80400c0600000000ULL

static const uint64_t RC[12] = {
    0xf0ULL << 56, 0xe1ULL << 56, 0xd2ULL << 56, 0xc3ULL << 56,
    0xb4ULL << 56, 0xa5ULL << 56, 0x96ULL << 56, 0x87ULL << 56,
    0x78ULL << 56, 0x69ULL << 56, 0x5aULL << 56, 0x4bULL << 56
};

/* ---------- utils ---------- */
static uint64_t load64(const uint8_t *b){
    uint64_t x=0;
    for(int i=0;i<8;i++) x=(x<<8)|b[i];
    return x;
}

static void store64(uint8_t *b,uint64_t x){
    for(int i=7;i>=0;i--){
        b[i]=x&0xff;
        x>>=8;
    }
}

static uint64_t rotr(uint64_t x,int n){
    return (x>>n)|(x<<(64-n));
}

/* ---------- S-BOX (EXTRACTED) ---------- */
void __attribute__((noinline)) ascon_sbox(state_t *s)
{
    uint64_t t0=~s->x0,t1=~s->x1,t2=~s->x2,t3=~s->x3,t4=~s->x4;

    s->x0 ^= (t1 & s->x2);
    s->x1 ^= (t2 & s->x3);
    s->x2 ^= (t3 & s->x4);
    s->x3 ^= (t4 & s->x0);
    s->x4 ^= (t0 & s->x1);

    s->x1 ^= s->x0;
    s->x0 ^= s->x4;
    s->x3 ^= s->x2;
    s->x2 = ~s->x2;
}

/* ---------- permutation ---------- */
void __attribute__((noinline)) side_channel_probe(uint8_t value);

void __attribute__((noinline)) ascon_round(state_t *s,int r){
    s->x2 ^= RC[r];

    /* call S-box as separate function */
    ascon_sbox(s);
    side_channel_probe((uint8_t)s->x0);

    s->x0 ^= rotr(s->x0,19) ^ rotr(s->x0,28);
    s->x1 ^= rotr(s->x1,61) ^ rotr(s->x1,39);
    s->x2 ^= rotr(s->x2,1)  ^ rotr(s->x2,6);
    s->x3 ^= rotr(s->x3,10) ^ rotr(s->x3,17);
    s->x4 ^= rotr(s->x4,7)  ^ rotr(s->x4,41);
}

void __attribute__((noinline)) permute(state_t *s,int rounds){
    for(int i=0;i<rounds;i++) ascon_round(s,i);
}

/* ----- debug helpers ----- */
static int ascon_verbose = 0;
static volatile uint8_t trace_probe_sink;

void __attribute__((noinline)) side_channel_probe(uint8_t value)
{
    trace_probe_sink = value;
}

static void dump_state(const char *tag, state_t *s){
    if(!ascon_verbose) return;
    printf("%s: x0=%016llx x1=%016llx x2=%016llx x3=%016llx x4=%016llx\n",
           tag,
           (unsigned long long)s->x0,
           (unsigned long long)s->x1,
           (unsigned long long)s->x2,
           (unsigned long long)s->x3,
           (unsigned long long)s->x4);
}

/* ---------- ENCRYPT ---------- */
void ascon128_encrypt(
    const uint8_t *k,
    const uint8_t *n,
    const uint8_t *ad,size_t adlen,
    const uint8_t *pt,size_t ptlen,
    uint8_t *ct,
    uint8_t *tag)
{
    state_t s;
    uint8_t buf[8];

    s.x0=IV;
    s.x1=load64(k);
    s.x2=load64(k+8);
    s.x3=load64(n);
    s.x4=load64(n+8);

    permute(&s,12);

    s.x3 ^= load64(k);
    s.x4 ^= load64(k+8);

    while(adlen>=RATE){
        s.x0 ^= load64(ad);
        permute(&s,6);
        ad+=RATE; adlen-=RATE;
    }

    memset(buf,0,8);
    memcpy(buf,ad,adlen);
    buf[adlen]=0x80;
    s.x0 ^= load64(buf);
    permute(&s,6);

    s.x4 ^= 1;

    while(ptlen>=RATE){
        s.x0 ^= load64(pt);
        store64(ct,s.x0);
        permute(&s,6);
        pt+=RATE; ct+=RATE; ptlen-=RATE;
    }

    memset(buf,0,8);
    memcpy(buf,pt,ptlen);
    buf[ptlen]=0x80;
    s.x0 ^= load64(buf);

    store64(buf,s.x0);
    memcpy(ct,buf,ptlen);

    permute(&s,12);

    s.x3 ^= load64(k);
    s.x4 ^= load64(k+8);

    store64(tag,s.x3);
    store64(tag+8,s.x4);
}

/* ---------- DECRYPT ---------- */
int ascon128_decrypt(
    const uint8_t *k,
    const uint8_t *n,
    const uint8_t *ad,size_t adlen,
    const uint8_t *ct,size_t ctlen,
    const uint8_t *tag,
    uint8_t *pt)
{
    state_t s;
    uint8_t buf[8],t[16];

    uint8_t *tmp=malloc(ctlen?ctlen:1);
    uint8_t *tp=tmp;
    const uint8_t *cp=ct;

    s.x0=IV;
    s.x1=load64(k);
    s.x2=load64(k+8);
    s.x3=load64(n);
    s.x4=load64(n+8);

    dump_state("init", &s);

    permute(&s,12);

    dump_state("after permute(12)", &s);

    s.x3 ^= load64(k);
    s.x4 ^= load64(k+8);

    dump_state("after key xor (start decryption)", &s);

    while(adlen>=RATE){
        s.x0 ^= load64(ad);
        dump_state("after absorb AD block (dec)", &s);
        permute(&s,6);
        dump_state("after permute(6) (AD) (dec)", &s);
        ad+=RATE; adlen-=RATE;
    }

    memset(buf,0,8);
    memcpy(buf,ad,adlen);
    buf[adlen]=0x80;
    s.x0 ^= load64(buf);
    permute(&s,6);

    s.x4 ^= 1;

    dump_state("after domain separation (dec)", &s);

    size_t r=ctlen;

    while(r>=RATE){
        uint64_t c=load64(cp);
        store64(tp,s.x0^c);
        s.x0=c;
        dump_state("after load ciphertext into x0 (dec)", &s);
        permute(&s,6);
        dump_state("after permute(6) (dec block)", &s);
        cp+=RATE; tp+=RATE; r-=RATE;
    }

    if(r){
        store64(buf,s.x0);
        for(size_t i=0;i<r;i++) tp[i]=buf[i]^cp[i];
        memset(buf,0,8);
        memcpy(buf,tp,r);
        buf[r]=0x80;
        s.x0^=load64(buf);
        dump_state("after partial recover and pad (dec)", &s);
    }

    permute(&s,12);

    dump_state("after final permute(12) (dec)", &s);

    s.x3 ^= load64(k);
    s.x4 ^= load64(k+8);

    store64(t,s.x3);
    store64(t+8,s.x4);

    uint8_t d=0;
    for(int i=0;i<16;i++) d|=t[i]^tag[i];

    if(d){ free(tmp); return -1; }

    memcpy(pt,tmp,ctlen);
    free(tmp);
    return 0;
}