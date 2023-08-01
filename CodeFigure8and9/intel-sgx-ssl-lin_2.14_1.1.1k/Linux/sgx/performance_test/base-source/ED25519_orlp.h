#ifdef  __cplusplus
extern "C" {
#endif

#include <stddef.h>


/*
    Portable header to provide the 32 and 64 bits type.

    Not a compatible replacement for <stdint.h>, do not blindly use it as such.
*/

#if ((defined(__STDC__) && __STDC__ && __STDC_VERSION__ >= 199901L) || (defined(__WATCOMC__) && (defined(_STDINT_H_INCLUDED) || __WATCOMC__ >= 1250)) || (defined(__GNUC__) && (defined(_STDINT_H) || defined(_STDINT_H_) || defined(__UINT_FAST64_TYPE__)) )) && !defined(FIXEDINT_H_INCLUDED)
    #include <stdint.h>
    #define FIXEDINT_H_INCLUDED

    #if defined(__WATCOMC__) && __WATCOMC__ >= 1250 && !defined(UINT64_C)
        #include <limits.h>
        #define UINT64_C(x) (x + (UINT64_MAX - UINT64_MAX))
    #endif
#endif


#ifndef FIXEDINT_H_INCLUDED
    #define FIXEDINT_H_INCLUDED
    
    #include <limits.h>

    /* (u)int32_t */
    #ifndef uint32_t
        #if (ULONG_MAX == 0xffffffffUL)
            typedef unsigned long uint32_t;
        #elif (UINT_MAX == 0xffffffffUL)
            typedef unsigned int uint32_t;
        #elif (USHRT_MAX == 0xffffffffUL)
            typedef unsigned short uint32_t;
        #endif
    #endif


    #ifndef int32_t
        #if (LONG_MAX == 0x7fffffffL)
            typedef signed long int32_t;
        #elif (INT_MAX == 0x7fffffffL)
            typedef signed int int32_t;
        #elif (SHRT_MAX == 0x7fffffffL)
            typedef signed short int32_t;
        #endif
    #endif


    /* (u)int64_t */
    #if (defined(__STDC__) && defined(__STDC_VERSION__) && __STDC__ && __STDC_VERSION__ >= 199901L)
        typedef long long int64_t;
        typedef unsigned long long uint64_t;

        #define UINT64_C(v) v ##ULL
        #define INT64_C(v) v ##LL
    #elif defined(__GNUC__)
        __extension__ typedef long long int64_t;
        __extension__ typedef unsigned long long uint64_t;

        #define UINT64_C(v) v ##ULL
        #define INT64_C(v) v ##LL
    #elif defined(__MWERKS__) || defined(__SUNPRO_C) || defined(__SUNPRO_CC) || defined(__APPLE_CC__) || defined(_LONG_LONG) || defined(_CRAYC)
        typedef long long int64_t;
        typedef unsigned long long uint64_t;

        #define UINT64_C(v) v ##ULL
        #define INT64_C(v) v ##LL
    #elif (defined(__WATCOMC__) && defined(__WATCOM_INT64__)) || (defined(_MSC_VER) && _INTEGRAL_MAX_BITS >= 64) || (defined(__BORLANDC__) && __BORLANDC__ > 0x460) || defined(__alpha) || defined(__DECC)
        typedef __int64 int64_t;
        typedef unsigned __int64 uint64_t;

        #define UINT64_C(v) v ##UI64
        #define INT64_C(v) v ##I64
    #endif
#endif




typedef int32_t fe[10];

/* state */
typedef struct sha512_context_ {
    uint64_t  length, state[8];
    size_t curlen;
    unsigned char buf[128];
} sha512_context;

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p1p1;

typedef struct {
  fe yplusx;
  fe yminusx;
  fe xy2d;
} ge_precomp;

typedef struct {
  fe YplusX;
  fe YminusX;
  fe Z;
  fe T2d;
} ge_cached;

    static void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);
    static void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
    static void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
    static int  ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);


    static void cmov(ge_precomp *t, const ge_precomp *u, unsigned char b);
    static unsigned char equal(signed char b, signed char c);    
    static unsigned char negative(signed char b);    
    static void select_ed(ge_precomp *t, int pos, signed char b);


    //aux fe.h

    static void fe_0(fe h);
    static void fe_1(fe h);

    static void fe_frombytes(fe h, const unsigned char *s);
    static void fe_tobytes(unsigned char *s, const fe h);

    static void fe_copy(fe h, const fe f);
    static int fe_isnegative(const fe f);
    static int fe_isnonzero(const fe f);
    static void fe_cmov(fe f, const fe g, unsigned int b);
    static void fe_cswap(fe f, fe g, unsigned int b);

    static void fe_neg(fe h, const fe f);
    static void fe_add(fe h, const fe f, const fe g);
    static void fe_invert(fe out, const fe z);
    static void fe_sq(fe h, const fe f);
    static void fe_sq2(fe h, const fe f);
    static void fe_mul(fe h, const fe f, const fe g);
    static void fe_mul121666(fe h, fe f);
    static void fe_pow22523(fe out, const fe z);
    static void fe_sub(fe h, const fe f, const fe g);


    //aux sha512

    static int sha512_init(sha512_context * md);
    static int sha512_final(sha512_context * md, unsigned char *out);
    static int sha512_update(sha512_context * md, const unsigned char *in, size_t inlen);
    static int sha512(const unsigned char *message, size_t message_len, unsigned char *out);


    //aux ge.h

    static void ge_p3_tobytes(unsigned char *s, const ge_p3 *h);
    static void ge_tobytes(unsigned char *s, const ge_p2 *h);
    static int ge_frombytes_negate_vartime(ge_p3 *h, const unsigned char *s);

    static void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
    static void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
    static void ge_double_scalarmult_vartime(ge_p2 *r, const unsigned char *a, const ge_p3 *A, const unsigned char *b);
    static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q);
    static void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q);
    static void ge_scalarmult_base(ge_p3 *h, const unsigned char *a);

    static void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p);
    static void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p);
    static void ge_p2_0(ge_p2 *h);
    static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p);
    static void ge_p3_0(ge_p3 *h);
    static void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p);
    static void ge_p3_to_cached(ge_cached *r, const ge_p3 *p);
    static void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p);

    //aux sc.c
    static void sc_reduce(unsigned char *s);
    static void sc_muladd(unsigned char *s, const unsigned char *a, const unsigned char *b, const unsigned char *c);  


#ifdef  __cplusplus
}
#endif
