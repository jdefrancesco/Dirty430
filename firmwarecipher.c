/*
 rc4_variants_msp430.c
 Build for MSP430F5438: msp430-gcc -mmcu=msp430f5438 -Os -g -o rc4_variants.elf rc4_variants_msp430.c

 This file implements:
  - RC4 (standard)
  - RC4-dropN
  - RC4 with KSA repeated 3 times (KSAx3)
  - RC4A (two S boxes)
  - VMPC
 Each variant writes a keystream blob into a global buffer so you can load the ELF in Ghidra
 and inspect S arrays, i/j indices, and keystream output.
*/

#include <msp430.h>
#include <stdint.h>
#include <string.h>

/* Expose arrays/symbols as global so Ghidra can find them. */
#define S_LEN 256
#define OUTLEN 512
#define DROP_N 768

/* Keys (different per variant to help distinguish) */
static const uint8_t key_rc4[]     = {0x10,0x20,0x30,0x40,0x50,0x60,0x70};
static const uint8_t key_drop[]    = {0x11,0x22,0x33,0x44,0x55};
static const uint8_t key_ksa3[]    = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
static const uint8_t key_rc4a[]    = {0x01,0x02,0x03,0x04,0x05,0x06};
static const uint8_t key_vmpc[]    = {0x5a,0xa5,0x5a,0xa5,0x00};

/* Output buffers (volatile to prevent aggressive compiler folding) */
volatile uint8_t out_rc4[OUTLEN];
volatile uint8_t out_rc4_drop[OUTLEN];
volatile uint8_t out_rc4_ksa3[OUTLEN];
volatile uint8_t out_rc4a[OUTLEN];
volatile uint8_t out_vmpc[OUTLEN];

/* Permutation arrays and indices - exported for analysis */
volatile uint8_t S_std[S_LEN];
volatile uint8_t S_drop[S_LEN];
volatile uint8_t S_ksa3[S_LEN];
volatile uint8_t S1_rc4a[S_LEN];
volatile uint8_t S2_rc4a[S_LEN];
volatile uint8_t S_vmpc[S_LEN];

/* Utility: initialize permutation to identity */
static void perm_init(volatile uint8_t *S) {
    for (int i = 0; i < S_LEN; ++i) S[i] = (uint8_t)i;
}

/* Standard RC4 KSA */
static void rc4_ksa(volatile uint8_t *S, const uint8_t *key, int keylen) {
    uint8_t j = 0;
    for (int i = 0; i < S_LEN; ++i) {
        j = (uint8_t)(j + S[i] + key[i % keylen]);
        /* swap S[i], S[j] */
        uint8_t tmp = S[i];
        ((uint8_t*)S)[i] = ((uint8_t*)S)[j];
        ((uint8_t*)S)[j] = tmp;
    }
}

/* Standard RC4 PRGA -> fill out buffer */
static void rc4_prga(volatile uint8_t *S, uint8_t *out, int outlen) {
    uint8_t i = 0, j = 0;
    for (int k = 0; k < outlen; ++k) {
        i = (uint8_t)(i + 1);
        j = (uint8_t)(j + S[i]);
        /* swap S[i], S[j] */
        uint8_t tmp = S[i];
        ((uint8_t*)S)[i] = ((uint8_t*)S)[j];
        ((uint8_t*)S)[j] = tmp;
        uint8_t t = (uint8_t)(S[i] + S[j]);
        out[k] = S[t];
    }
}

/* RC4-dropN: do PRGA but discard first DROP_N bytes */
static void rc4_prga_drop(volatile uint8_t *S, uint8_t *out, int outlen, int drop) {
    uint8_t i = 0, j = 0;
    for (int d = 0; d < drop; ++d) {
        i = (uint8_t)(i + 1);
        j = (uint8_t)(j + S[i]);
        uint8_t tmp = S[i];
        ((uint8_t*)S)[i] = ((uint8_t*)S)[j];
        ((uint8_t*)S)[j] = tmp;
        /* discard S[ S[i] + S[j] ] */
        (void) S[(uint8_t)(S[i] + S[j])];
    }
    for (int k = 0; k < outlen; ++k) {
        i = (uint8_t)(i + 1);
        j = (uint8_t)(j + S[i]);
        uint8_t tmp = S[i];
        ((uint8_t*)S)[i] = ((uint8_t*)S)[j];
        ((uint8_t*)S)[j] = tmp;
        out[k] = S[(uint8_t)(S[i] + S[j])];
    }
}

/* RC4 with KSA repeated 3x (KSAx3). Useful to emulate stronger KSA variants. */
static void rc4_ksa_x_times(volatile uint8_t *S, const uint8_t *key, int keylen, int times) {
    for (int t = 0; t < times; ++t) {
        uint8_t j = 0;
        for (int i = 0; i < S_LEN; ++i) {
            j = (uint8_t)(j + S[i] + key[i % keylen]);
            uint8_t tmp = S[i];
            ((uint8_t*)S)[i] = ((uint8_t*)S)[j];
            ((uint8_t*)S)[j] = tmp;
        }
    }
}

/* RC4A implementation (per Paul & Preneel): two-state variant
   Pseudocode (high level):
    i := 0; j1 := 0; j2 := 0;
    loop:
      i := i+1;
      j1 := j1 + S1[i];
      swap S1[i], S1[j1];
      output byte := S2[(S1[i] + S1[j1]) mod 256];
      j2 := j2 + S2[i];
      swap S2[i], S2[j2];
      output byte := S1[(S2[i] + S2[j2]) mod 256];
*/
static void rc4a_generate(volatile uint8_t *S1, volatile uint8_t *S2, uint8_t *out, int outlen) {
    uint8_t i = 0;
    uint8_t j1 = 0, j2 = 0;
    int k = 0;
    while (k < outlen) {
        i = (uint8_t)(i + 1);
        j1 = (uint8_t)(j1 + S1[i]);
        { uint8_t tmp = S1[i]; ((uint8_t*)S1)[i] = ((uint8_t*)S1)[j1]; ((uint8_t*)S1)[j1] = tmp; }
        out[k++] = S2[(uint8_t)(S1[i] + S1[j1])];
        if (k >= outlen) break;
        j2 = (uint8_t)(j2 + S2[i]);
        { uint8_t tmp = S2[i]; ((uint8_t*)S2)[i] = ((uint8_t*)S2)[j2]; ((uint8_t*)S2)[j2] = tmp; }
        out[k++] = S1[(uint8_t)(S2[i] + S2[j2])];
    }
}

/* VMPC KSA: similar to RC4 but performed 3 * 256 iterations in VMPC proposals.
   VMPC PRGA (as per VMPC description):
     i := 0;
     while (generating):
       j := S[(j + S[i]) mod 256];
       output := S[(S[S[j]] + 1) mod 256];
       swap S[i], S[j];
       i := i + 1;
*/
static void vmpc_ksa(volatile uint8_t *S, const uint8_t *key, int keylen) {
    uint8_t j = 0;
    /* Initialize S to identity done by caller */
    /* The VMPC proposal runs 3*256 iterations for stronger mixing */
    for (int round = 0; round < 3; ++round) {
        for (int i = 0; i < S_LEN; ++i) {
            j = (uint8_t)(j + S[i] + key[i % keylen]);
            uint8_t tmp = S[i];
            ((uint8_t*)S)[i] = ((uint8_t*)S)[j];
            ((uint8_t*)S)[j] = tmp;
        }
    }
}

/* VMPC PRGA */
static void vmpc_prga(volatile uint8_t *S, uint8_t *out, int outlen) {
    uint8_t i = 0;
    uint8_t j = 0;
    for (int k = 0; k < outlen; ++k) {
        j = (uint8_t)(S[(uint8_t)(j + S[i])]);
        uint8_t t = (uint8_t)(S[(uint8_t)(S[(uint8_t)j] + 1)]);
        out[k] = t;
        uint8_t tmp = S[i];
        ((uint8_t*)S)[i] = ((uint8_t*)S)[j];
        ((uint8_t*)S)[j] = tmp;
        i = (uint8_t)(i + 1);
    }
}

/* Simple memory barrier-like noop to keep symbols alive in optimized builds */
static void touch_memory(void) {
    volatile uint8_t tmp = 0;
    tmp ^= out_rc4[0];
    tmp ^= out_rc4_drop[0];
    tmp ^= out_rc4_ksa3[0];
    tmp ^= out_rc4a[0];
    tmp ^= out_vmpc[0];
    (void) tmp;
}

/* Entry point */
int main(void) {
    WDTCTL = WDTPW | WDTHOLD;   // stop watchdog

    /* 1) Standard RC4 */
    perm_init(S_std);
    rc4_ksa(S_std, key_rc4, sizeof(key_rc4));
    rc4_prga(S_std, (uint8_t*)out_rc4, OUTLEN);

    /* 2) RC4-drop (drop first DROP_N bytes) */
    perm_init(S_drop);
    rc4_ksa(S_drop, key_drop, sizeof(key_drop));
    rc4_prga_drop(S_drop, (uint8_t*)out_rc4_drop, OUTLEN, DROP_N);

    /* 3) RC4 with KSA x3 */
    perm_init(S_ksa3);
    rc4_ksa_x_times(S_ksa3, key_ksa3, sizeof(key_ksa3), 3);
    rc4_prga(S_ksa3, (uint8_t*)out_rc4_ksa3, OUTLEN);

    /* 4) RC4A */
    perm_init(S1_rc4a);
    perm_init(S2_rc4a);
    /* Use same KSA for both S1 and S2 (common RC4A initialization approach) */
    rc4_ksa(S1_rc4a, key_rc4a, sizeof(key_rc4a));
    rc4_ksa(S2_rc4a, key_rc4a, sizeof(key_rc4a));
    rc4a_generate(S1_rc4a, S2_rc4a, (uint8_t*)out_rc4a, OUTLEN);

    /* 5) VMPC */
    perm_init(S_vmpc);
    vmpc_ksa(S_vmpc, key_vmpc, sizeof(key_vmpc));
    vmpc_prga(S_vmpc, (uint8_t*)out_vmpc, OUTLEN);

    /* prevent compiler from optimizing out */
    touch_memory();

    /* Halt CPU - results live in global memory for inspection */
    __bis_SR_register(LPM4_bits + GIE);
    while (1) { }
    return 0;
}
