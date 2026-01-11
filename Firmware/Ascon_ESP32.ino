/**
 * Ascon AEAD Cryptographic Implementation for ESP32
 * Single File Arduino Sketch
 * 
 * This is a complete implementation of the Ascon AEAD cipher
 * optimized for ESP32 microcontroller using Arduino IDE.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <esp_system.h>
#include <DHT.h>

// ===========================
// WiFi Configuration
// ===========================

#define WIFI_SSID "SSID_Here"
#define WIFI_PASSWORD "Pass_Key"
#define SERVER_IP "192.168.43.x"
// Add your Server/End Device's IP, recommended to use a Static one
#define SERVER_PORT 8080

#define SERVER_URL "http://192.168.43.x:8080/data"
// Update URL with accordance to IP and Port


// ===========================
// Configuration & Constants
// ===========================

#define CRYPTO_VERSION "1.3.0"
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1
#define ASCON_AEAD_RATE 16
#define ASCON_VARIANT 1

// Constants
#define ASCON_80PQ_VARIANT 0
#define ASCON_AEAD_VARIANT 1
#define ASCON_HASH_VARIANT 2
#define ASCON_XOF_VARIANT 3
#define ASCON_CXOF_VARIANT 4
#define ASCON_MAC_VARIANT 5
#define ASCON_PRF_VARIANT 6
#define ASCON_PRFS_VARIANT 7

#define ASCON_TAG_SIZE 16
#define ASCON_HASH_SIZE 32

#define ASCON_128_RATE 8
#define ASCON_128A_RATE 16
#define ASCON_HASH_RATE 8
#define ASCON_PRF_IN_RATE 32
#define ASCON_PRFA_IN_RATE 40
#define ASCON_PRF_OUT_RATE 16

#define ASCON_PA_ROUNDS 12
#define ASCON_128_PB_ROUNDS 6
#define ASCON_128A_PB_ROUNDS 8
#define ASCON_HASH_PB_ROUNDS 12
#define ASCON_HASHA_PB_ROUNDS 8
#define ASCON_PRF_PB_ROUNDS 12
#define ASCON_PRFA_PB_ROUNDS 8

#define ASCON_128_IV 0x00000800806c0001ull
#define ASCON_128A_IV 0x00001000808c0001ull
#define ASCON_80PQ_IV 0x00000000806c0800ull

#define ASCON_HASH_IV 0x0000080100cc0002ull
#define ASCON_HASHA_IV 0x00000801008c0002ull
#define ASCON_XOF_IV 0x0000080000cc0003ull
#define ASCON_XOFA_IV 0x00000800008c0003ull
#define ASCON_CXOF_IV 0x0000080000cc0004ull
#define ASCON_CXOFA_IV 0x00000800008c0004ull

#define ASCON_MAC_IV 0x0010200080cc0005ull
#define ASCON_MACA_IV 0x00102800808c0005ull
#define ASCON_PRF_IV 0x0010200000cc0006ull
#define ASCON_PRFA_IV 0x00102800008c0006ull
#define ASCON_PRFS_IV 0x00000000800c0007ull

#define ASCON_HASH_IV0 0x9b1e5494e934d681ull
#define ASCON_HASH_IV1 0x4bc3a01e333751d2ull
#define ASCON_HASH_IV2 0xae65396c6b34b81aull
#define ASCON_HASH_IV3 0x3c7fd4a4d56a4db3ull
#define ASCON_HASH_IV4 0x1a5c464906c5976dull

#define ASCON_HASHA_IV0 0xe2ffb4d17ffcadc5ull
#define ASCON_HASHA_IV1 0xdd364b655fa88cebull
#define ASCON_HASHA_IV2 0xdcaabe85a70319d2ull
#define ASCON_HASHA_IV3 0xd98f049404be3214ull
#define ASCON_HASHA_IV4 0xca8c9d516e8a2221ull

#define ASCON_XOF_IV0 0xda82ce768d9447ebull
#define ASCON_XOF_IV1 0xcc7ce6c75f1ef969ull
#define ASCON_XOF_IV2 0xe7508fd780085631ull
#define ASCON_XOF_IV3 0x0ee0ea53416b58ccull
#define ASCON_XOF_IV4 0xe0547524db6f0bdeull

#define ASCON_XOFA_IV0 0xf3040e5017d92943ull
#define ASCON_XOFA_IV1 0xc474f6e3ae01892eull
#define ASCON_XOFA_IV2 0xbf5cb3ca954805e0ull
#define ASCON_XOFA_IV3 0xd9c28702ccf962efull
#define ASCON_XOFA_IV4 0x5923fa01f4b0e72full

#define RC0 0xf0
#define RC1 0xe1
#define RC2 0xd2
#define RC3 0xc3
#define RC4 0xb4
#define RC5 0xa5
#define RC6 0x96
#define RC7 0x87
#define RC8 0x78
#define RC9 0x69
#define RCa 0x5a
#define RCb 0x4b

#define RC(i) (i)

#define START(n) ((3 + (n)) << 4 | (12 - (n)))
#define INC -0x0f
#define END 0x3c

// Endianness handling
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || \
    defined(_MSC_VER)
#define U64LE(x) (x)
#define U32LE(x) (x)
#define U16LE(x) (x)
#elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define U64LE(x)                           \
  (((0x00000000000000FFULL & (x)) << 56) | \
   ((0x000000000000FF00ULL & (x)) << 40) | \
   ((0x0000000000FF0000ULL & (x)) << 24) | \
   ((0x00000000FF000000ULL & (x)) << 8) |  \
   ((0x000000FF00000000ULL & (x)) >> 8) |  \
   ((0x0000FF0000000000ULL & (x)) >> 24) | \
   ((0x00FF000000000000ULL & (x)) >> 40) | \
   ((0xFF00000000000000ULL & (x)) >> 56))
#define U32LE(x)                                            \
  (((0x000000FF & (x)) << 24) | ((0x0000FF00 & (x)) << 8) | \
   ((0x00FF0000 & (x)) >> 8) | ((0xFF000000 & (x)) >> 24))
#define U16LE(x) (((0x00FF & (x)) << 8) | ((0xFF00 & (x)) >> 8))
#else
#define U64LE(x) (x)
#define U32LE(x) (x)
#define U16LE(x) (x)
#endif

// ===========================
// Type Definitions
// ===========================

typedef union {
  uint64_t x;
  struct {
    uint32_t l;
    uint32_t h;
  };
} uint32x2_t;

typedef union {
  uint64_t x[5];
  uint32x2_t w[5];
  uint8_t b[5][8];
} ascon_state_t;

// ===========================
// Core Definitions
// ===========================

#define ASCON_AD 0
#define ASCON_ENC 1
#define ASCON_DEC 2

#define PA_START_ROUND 0xf0

#if ASCON_AEAD_RATE == 8
#define PB_START_ROUND 0x96
#else
#define PB_START_ROUND 0xb4
#endif

// Disable state printing for Arduino (Memory Constraints)
#define print(text) do { } while (0)
#define printbytes(text, b, l) do { } while (0)
#define printword(text, w) do { } while (0)
#define printstate(text, s) do { } while (0)

// Shared key for ASCON-128a (16 bytes)
// Key : 000102030405060708090A0B0C0D0E0F , change if neccassary, also if changed update the key on the server side
static const unsigned char ASCON_KEY[CRYPTO_KEYBYTES] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// ===========================
// Permutation Macros
// ===========================

#define START_ROUND(x) (12 - (x))
#define LAST_ROUND 0x4b

#define SBOX(x0, x1, x2, x3, x4, r0, t0, t1, t2) \
  do {                                           \
    t1 = x0 ^ x4;                                \
    t2 = x3 ^ x4;                                \
    t0 = -1;                                     \
    x4 = x4 ^ t0;                                \
    t0 = x1 ^ x2;                                \
    x4 = x4 | x3;                                \
    x4 = x4 ^ t0;                                \
    x3 = x3 ^ x1;                                \
    x3 = x3 | t0;                                \
    x3 = x3 ^ t1;                                \
    x2 = x2 ^ t1;                                \
    x2 = x2 | x1;                                \
    x2 = x2 ^ t2;                                \
    x0 = x0 | t2;                                \
    x0 = x0 ^ t0;                                \
    t0 = -1;                                     \
    t1 = t1 ^ t0;                                \
    x1 = x1 & t1;                                \
    x1 = x1 ^ t2;                                \
    r0 = x0;                                     \
  } while (0)

#define SRC(o, h, l, amt)                 \
  do {                                    \
    o = (((uint64_t)h << 32) | l) >> amt; \
  } while (0)

#define LINEAR(dl, dh, sl, sh, sl0, sh0, r0, sl1, sh1, r1, t0) \
  do {                                                         \
    SRC(dl, sh0, sl0, r0);                                     \
    SRC(dh, sl0, sh0, r0);                                     \
    dl = dl ^ sl;                                              \
    dh = dh ^ sh;                                              \
    SRC(t0, sh1, sl1, r1);                                     \
    SRC(sh, sl1, sh1, r1);                                     \
    dl = dl ^ t0;                                              \
    dh = dh ^ sh;                                              \
  } while (0)

#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define lo h
#define hi l
#else
#define lo l
#define hi h
#endif

// ===========================
// Function Declarations
// ===========================

void P(ascon_state_t *p, uint8_t round_const);
void ascon_duplex(ascon_state_t* s, unsigned char* out, const unsigned char* in,
                  unsigned long len, uint8_t mode);
void ascon_core(ascon_state_t* s, unsigned char* out, const unsigned char* in,
                unsigned long long tlen, const unsigned char* ad,
                unsigned long long adlen, const unsigned char* npub,
                const unsigned char* k, uint8_t mode);
int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k);
int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k);

// ===========================
// Permutation Function P
// ===========================

void P(ascon_state_t *p, uint8_t round_const) {
  uint32_t x0h = p->w[0].hi, x0l = p->w[0].lo;
  uint32_t x1h = p->w[1].hi, x1l = p->w[1].lo;
  uint32_t x2h = p->w[2].hi, x2l = p->w[2].lo;
  uint32_t x3h = p->w[3].hi, x3l = p->w[3].lo;
  uint32_t x4h = p->w[4].hi, x4l = p->w[4].lo;
  uint32_t t0l, t0h;
  uint32_t rnd = round_const;
  uint32_t tmp0;

  while (rnd >= LAST_ROUND) {
    x2l ^= rnd;

    SBOX(x0l, x1l, x2l, x3l, x4l, t0l, t0h, t0l, tmp0);
    SBOX(x0h, x1h, x2h, x3h, x4h, t0h, t0h, x0l, tmp0);

    LINEAR(x0l, x0h, x2l, x2h, x2l, x2h, 19, x2l, x2h, 28, tmp0);
    LINEAR(x2l, x2h, x4l, x4h, x4l, x4h, 1, x4l, x4h, 6, tmp0);
    LINEAR(x4l, x4h, x1l, x1h, x1l, x1h, 7, x1h, x1l, 9, tmp0);
    LINEAR(x1l, x1h, x3l, x3h, x3h, x3l, 29, x3h, x3l, 7, tmp0);
    LINEAR(x3l, x3h, t0l, t0h, t0l, t0h, 10, t0l, t0h, 17, tmp0);

    rnd -= 15;
  }

  p->w[0].hi = x0h;
  p->w[0].lo = x0l;
  p->w[1].hi = x1h;
  p->w[1].lo = x1l;
  p->w[2].hi = x2h;
  p->w[2].lo = x2l;
  p->w[3].hi = x3h;
  p->w[3].lo = x3l;
  p->w[4].hi = x4h;
  p->w[4].lo = x4l;
}

// ===========================
// Ascon Duplex
// ===========================

void ascon_duplex(ascon_state_t* s, unsigned char* out, const unsigned char* in,
                  unsigned long len, uint8_t mode) {
#if ASCON_AEAD_RATE == 8
  uint32x2_t tmp[1], tmp0[1];
#else
  uint32x2_t tmp[2], tmp0[2];
#endif

  while (len >= ASCON_AEAD_RATE) {
    tmp[0].l = ((uint32_t*)in)[0];
    tmp[0].h = ((uint32_t*)in)[1];
    tmp[0].x = U64LE(tmp[0].x);
    s->w[0].h ^= tmp[0].h;
    s->w[0].l ^= tmp[0].l;
#if ASCON_AEAD_RATE == 16
    tmp[1].l = ((uint32_t*)in)[2];
    tmp[1].h = ((uint32_t*)in)[3];
    tmp[1].x = U64LE(tmp[1].x);
    s->w[1].h ^= tmp[1].h;
    s->w[1].l ^= tmp[1].l;
#endif

    if (mode != ASCON_AD) {
      tmp0[0] = s->w[0];
      tmp0[0].x = U64LE(tmp0[0].x);
      ((uint32_t*)out)[0] = tmp0[0].l;
      ((uint32_t*)out)[1] = tmp0[0].h;
#if ASCON_AEAD_RATE == 16
      tmp0[1] = s->w[1];
      tmp0[1].x = U64LE(tmp0[1].x);
      ((uint32_t*)out)[2] = tmp0[1].l;
      ((uint32_t*)out)[3] = tmp0[1].h;
#endif
    }
    if (mode == ASCON_DEC) {
      s->w[0] = tmp[0];
#if ASCON_AEAD_RATE == 16
      s->w[1] = tmp[1];
#endif
    }

    P(s, PB_START_ROUND);

    in += ASCON_AEAD_RATE;
    out += ASCON_AEAD_RATE;
    len -= ASCON_AEAD_RATE;
  }

  uint8_t* bytes = (uint8_t*)&tmp;
  memset(bytes, 0, sizeof tmp);
  memcpy(bytes, in, len);
  bytes[len] ^= 0x01;

  tmp[0].x = U64LE(tmp[0].x);
  s->w[0].h ^= tmp[0].h;
  s->w[0].l ^= tmp[0].l;
#if ASCON_AEAD_RATE == 16
  tmp[1].x = U64LE(tmp[1].x);
  s->w[1].h ^= tmp[1].h;
  s->w[1].l ^= tmp[1].l;
#endif

  if (mode != ASCON_AD) {
    tmp[0] = s->w[0];
    tmp[0].x = U64LE(tmp[0].x);
#if ASCON_AEAD_RATE == 16
    tmp[1] = s->w[1];
    tmp[1].x = U64LE(tmp[1].x);
#endif
    memcpy(out, bytes, len);
  }
  if (mode == ASCON_DEC) {
    memcpy(bytes, in, len);
    tmp[0].x = U64LE(tmp[0].x);
    s->w[0] = tmp[0];
#if ASCON_AEAD_RATE == 16
    tmp[1].x = U64LE(tmp[1].x);
    s->w[1] = tmp[1];
#endif
  }
}

// ===========================
// Ascon Core Function
// ===========================

void ascon_core(ascon_state_t* s, unsigned char* out, const unsigned char* in,
                unsigned long long tlen, const unsigned char* ad,
                unsigned long long adlen, const unsigned char* npub,
                const unsigned char* k, uint8_t mode) {
  uint32x2_t tmp[2];
  uint32x2_t K0, K1, N0, N1;

  // load key
  tmp[0].l = ((uint32_t*)k)[0];
  tmp[0].h = ((uint32_t*)k)[1];
  tmp[1].l = ((uint32_t*)k)[2];
  tmp[1].h = ((uint32_t*)k)[3];
  tmp[0].x = U64LE(tmp[0].x);
  tmp[1].x = U64LE(tmp[1].x);
  K0 = tmp[0];
  K1 = tmp[1];

  // load nonce
  tmp[0].l = ((uint32_t*)npub)[0];
  tmp[0].h = ((uint32_t*)npub)[1];
  tmp[1].l = ((uint32_t*)npub)[2];
  tmp[1].h = ((uint32_t*)npub)[3];
  tmp[0].x = U64LE(tmp[0].x);
  tmp[1].x = U64LE(tmp[1].x);
  N0 = tmp[0];
  N1 = tmp[1];

  // initialization
#if ASCON_AEAD_RATE == 8
  s->x[0] = ASCON_128_IV;
#else
  s->x[0] = ASCON_128A_IV;
#endif
  s->w[1].h = K0.h;
  s->w[1].l = K0.l;
  s->w[2].h = K1.h;
  s->w[2].l = K1.l;
  s->w[3].h = N0.h;
  s->w[3].l = N0.l;
  s->w[4].h = N1.h;
  s->w[4].l = N1.l;

  P(s, PA_START_ROUND);

  s->w[3].h ^= K0.h;
  s->w[3].l ^= K0.l;
  s->w[4].h ^= K1.h;
  s->w[4].l ^= K1.l;

  // process associated data
  if (adlen) {
    ascon_duplex(s, (unsigned char*)NULL, ad, adlen, ASCON_AD);
    P(s, PB_START_ROUND);
  }

  s->x[4] ^= 0x8000000000000000;

  // process plaintext/ciphertext
  ascon_duplex(s, out, in, tlen, mode);

  // finalization
#if ASCON_AEAD_RATE == 8
  s->w[1].h ^= K0.h;
  s->w[1].l ^= K0.l;
  s->w[2].h ^= K1.h;
  s->w[2].l ^= K1.l;
#else
  s->w[2].h ^= K0.h;
  s->w[2].l ^= K0.l;
  s->w[3].h ^= K1.h;
  s->w[3].l ^= K1.l;
#endif

  P(s, PA_START_ROUND);

  s->w[3].h ^= K0.h;
  s->w[3].l ^= K0.l;
  s->w[4].h ^= K1.h;
  s->w[4].l ^= K1.l;
  s->x[3] = U64LE(s->x[3]);
  s->x[4] = U64LE(s->x[4]);
}

// ===========================
// Encryption Function
// ===========================

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  ascon_state_t s;
  (void)nsec;

  // set Ciphertext size
  *clen = mlen + CRYPTO_ABYTES;
  print("encrypt\n");
  printbytes("k", k, CRYPTO_KEYBYTES);
  printbytes("n", npub, CRYPTO_NPUBBYTES);
  printbytes("a", ad, adlen);
  printbytes("m", m, mlen);

  ascon_core(&s, c, m, mlen, ad, adlen, npub, k, ASCON_ENC);

  // get tag
  int i;
  for (i = 0; i < CRYPTO_ABYTES; ++i) c[mlen + i] = *(s.b[3] + i);

  printbytes("c", c, mlen);
  printbytes("t", c + mlen, CRYPTO_ABYTES);
  print("\n");
  return 0;
}

// ===========================
// Decryption Function
// ===========================

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  if (clen < CRYPTO_ABYTES) {
    *mlen = 0;
    return -1;
  }

  ascon_state_t s;
  (void)nsec;

  // set plaintext size
  *mlen = clen - CRYPTO_ABYTES;
  print("decrypt\n");
  printbytes("k", k, CRYPTO_KEYBYTES);
  printbytes("n", npub, CRYPTO_NPUBBYTES);
  printbytes("a", ad, adlen);
  printbytes("c", c, *mlen);
  printbytes("t", c + *mlen, CRYPTO_ABYTES);

  ascon_core(&s, m, c, *mlen, ad, adlen, npub, k, ASCON_DEC);

  // verify should be constant time, check compiler output
  int i;
  int result = 0;
  for (i = 0; i < CRYPTO_ABYTES; ++i) result |= c[*mlen + i] ^ *(s.b[3] + i);
  result = (((result - 1) >> 8) & 1) - 1;

  printbytes("m", m, *mlen);
  print("\n");
  return result;
}

// Undefine macros that conflict with Serial.print()
#undef print
#undef printbytes
#undef printword
#undef printstate

// ===========================
// LED and Temperature Configuration
// ===========================

#define LED_PIN 2  // Built-in LED on GPIO 2, the ESP used for production on this side was an ESP-32-WROOM-32D, so update if neccassary
#define TEMP_INTERVAL 10000  // 10 seconds in milliseconds

// DHT sensor configuration (DATA pin -> GPIO15) or D15, update to your need
#define DHTPIN 15
#define DHTTYPE DHT11
DHT dht(DHTPIN, DHTTYPE);

// (No sensor-specific code in this sketch)

unsigned long lastTempTime = 0;
unsigned long messageNonce = 0;
bool wifiConnected = false;

// ===========================
// Calculate SHA256 Hash (simplified HMAC simulation)
// ===========================

void calculateIntegrityHash(const char* jsonData, char* hashOutput) {
  // Simple hash calculation (in production, use proper crypto library)
  unsigned long hash = 5381;
  for (int i = 0; jsonData[i] != '\0'; i++) {
    hash = ((hash << 5) + hash) ^ jsonData[i];
  }
  
  // Format as hex string (8 bytes)
  snprintf(hashOutput, 65,
    "%08lx%08lx%08lx%08lx%08lx%08lx%08lx%08lx",
    hash, hash ^ 0xA5A5A5A5, hash ^ 0x5A5A5A5A, hash ^ 0x12345678,
    hash ^ 0x87654321, hash ^ 0xDEADBEEF, hash ^ 0xCAFEBABE, hash ^ 0xFEEDFACE
  );
}

// Convert bytes to lowercase hex string (null-terminated)
void bytesToHex(const uint8_t* in, size_t len, char* out, size_t outSize) {
  static const char hex[] = "0123456789abcdef";
  size_t needed = len * 2 + 1;
  if (outSize < needed) return;
  for (size_t i = 0; i < len; i++) {
    out[2 * i] = hex[in[i] >> 4];
    out[2 * i + 1] = hex[in[i] & 0x0F];
  }
  out[needed - 1] = '\0';
}

// Encrypt JSON payload with Ascon-128a, returning hex nonce and ciphertext || tag

bool encryptAsconPayload(const char* plaintext, char* npubHexOut, size_t npubHexOutSize,
                         char* ctHexOut, size_t ctHexOutSize) {
  uint8_t npub[CRYPTO_NPUBBYTES];
  for (size_t i = 0; i < sizeof(npub); i++) npub[i] = (uint8_t)(esp_random() & 0xFF);

  size_t ptLen = strlen(plaintext);
  if (ptLen > 600) return false;  // guard buffer size

  uint8_t ciphertext[700];  // plaintext + 16-byte tag
  unsigned long long clen = 0;

  int rc = crypto_aead_encrypt(
    ciphertext, &clen,
    (const unsigned char*)plaintext, ptLen,
    NULL, 0,  // no associated data
    NULL, npub, ASCON_KEY
  );
  if (rc != 0) return false;

  bytesToHex(npub, sizeof(npub), npubHexOut, npubHexOutSize);
  bytesToHex(ciphertext, clen, ctHexOut, ctHexOutSize);
  return true;
}

// ===========================
// WiFi Connection Function
// ===========================

void connectToWiFi() {
  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);

  WiFi.mode(WIFI_STA);

  // Persistent connect loop: keep trying until we get an IP
  while (true) {
    if (WiFi.status() != WL_CONNECTED) {
      WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
      Serial.println("WiFi.begin() called, waiting for connection...");
    }

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED) {
      delay(500);
      Serial.print(".");
      attempts++;

      // Every ~5 seconds, print a status line and blink LED to indicate retry
      if (attempts % 10 == 0) {
        Serial.println();
        Serial.print("Still trying to connect (attempts="); Serial.print(attempts); Serial.println(")");
        for (int i = 0; i < 6; ++i) {
          digitalWrite(LED_PIN, HIGH);
          delay(100);
          digitalWrite(LED_PIN, LOW);
          delay(100);
        }
      }

      // Periodically re-trigger begin in case AP didnt see the previous attempt
      if (attempts % 60 == 0) {
        Serial.println("Re-sending WiFi.begin() to refresh association...");
        WiFi.disconnect();
        WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
      }
    }

    if (WiFi.status() == WL_CONNECTED) {
      wifiConnected = true;
      Serial.println("\nWiFi connected!");
      Serial.print("IP Address: ");
      Serial.println(WiFi.localIP());
      return;
    }

    // Small pause before retrying outer loop
    delay(1000);
  }
}

// Repeatedly attempts to contact the server. Blinks LED rapidly while trying.
bool waitForServerReachable(unsigned long retryDelayMs = 1000) {
  WiFiClient client;
  unsigned long attempt = 0;

  Serial.print("Checking server reachability: ");
  Serial.println(SERVER_URL);

  while (true) {
    if (!wifiConnected) {
      Serial.println("WiFi not connected; aborting server check.");
      return false;
    }

    attempt++;
    Serial.print("Server attempt #"); Serial.println(attempt);
    Serial.print("Destination: "); Serial.print(SERVER_IP); Serial.print(":"); Serial.println(SERVER_PORT);
    Serial.print("Local IP: "); Serial.println(WiFi.localIP());
    Serial.print("RSSI: "); Serial.print(WiFi.RSSI()); Serial.println(" dBm");

    if (client.connect(SERVER_IP, SERVER_PORT)) {
      Serial.println("Server reachable (TCP connect succeeded).");
      client.stop();
      return true;
    }

    Serial.println("Server not reachable yet — blinking LED while retrying.");

    // Rapid blink sequence indicating server attempts
    for (int i = 0; i < 6; ++i) {
      digitalWrite(LED_PIN, HIGH);
      delay(100);
      digitalWrite(LED_PIN, LOW);
      delay(100);
    }

    delay(retryDelayMs);
  }

  return false;
}

// ===========================
// Send Data to Server Function
// ===========================

void sendDataToLaptop(const char* data) {
  if (!wifiConnected) {
    Serial.println("WiFi not connected. Attempting to reconnect...");
    connectToWiFi();
  }
  
  if (wifiConnected) {
    Serial.print("Sending to: "); Serial.println(SERVER_URL);
    Serial.print("Destination: "); Serial.print(SERVER_IP); Serial.print(":"); Serial.println(SERVER_PORT);
    Serial.print("Local IP: "); Serial.println(WiFi.localIP());
    Serial.print("RSSI: "); Serial.print(WiFi.RSSI()); Serial.println(" dBm");

    HTTPClient http;
    http.begin(SERVER_URL);
    http.addHeader("Content-Type", "application/json");
    
    int httpResponseCode = http.POST(data);
    
    if (httpResponseCode > 0) {
      Serial.print("Data sent successfully! Response code: ");
      Serial.println(httpResponseCode);
      String response = http.getString();
      Serial.print("Response: ");
      Serial.println(response);
    } else {
      Serial.print("Error sending data. Code: ");
      Serial.println(httpResponseCode);
    }
    http.end();
  }
}

// ===========================
// Arduino Setup
// ===========================

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  delay(2000);  // Allow time for Serial to initialize
  
  Serial.println("\n\n-----------");
  Serial.println("Test");
  Serial.print("Version: ");
  Serial.println(CRYPTO_VERSION);
  Serial.println("-----------");
  Serial.println("WiFi Enabled");
  Serial.println("LED will flash whilst sending data\n");
  
  // Connect to WiFi
  connectToWiFi();
  // After WiFi connects, wait until the server is reachable (TCP)
  if (wifiConnected) {
    if (waitForServerReachable(1000)) {
      Serial.println("Server is reachable — continuing startup.");
    } else {
      Serial.println("Server unreachable — continuing but sends may fail.");
    }
  }
  // Initialize DHT sensor
  dht.begin();
  Serial.println("DHT initialized");
  
  // Test Data
  unsigned char nonce[CRYPTO_NPUBBYTES] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  };
  
  unsigned char ad[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
  };
  
  unsigned char plaintext[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  
  size_t ad_len = sizeof(ad);
  size_t pt_len = sizeof(plaintext);
  
  // Buffer for ciphertext (plaintext + tag)
  unsigned char ciphertext[sizeof(plaintext) + CRYPTO_ABYTES];
  unsigned long long clen = 0;
  
  // Buffer for decrypted plaintext
  unsigned char decrypted[sizeof(plaintext)];
  unsigned long long dlen = 0;
  
  // === Encryption ===
  Serial.println("\n=== Encryption ===");
  int encrypt_result = crypto_aead_encrypt(
    ciphertext, &clen,
    plaintext, pt_len,
    ad, ad_len,
    NULL,  // nsec (unused)
    nonce,
    ASCON_KEY
  );
  
  Serial.print("Encryption result: ");
  Serial.println(encrypt_result);
  Serial.print("Ciphertext length: ");
  Serial.println((unsigned long)clen);
  
  Serial.print("Ciphertext: ");
  for (int i = 0; i < clen; i++) {
    if (ciphertext[i] < 0x10) Serial.print("0");
    Serial.print(ciphertext[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
  
  // === Decryption ===
  Serial.println("\n--- Decryption ---");
  int decrypt_result = crypto_aead_decrypt(
    decrypted, &dlen,
    NULL,  // nsec (unused)
    ciphertext, clen,
    ad, ad_len,
    nonce,
    ASCON_KEY
  );
  
  Serial.print("Decryption result: ");
  Serial.println(decrypt_result);
  Serial.print("Decrypted length: ");
  Serial.println((unsigned long)dlen);
  
  Serial.print("Decrypted: ");
  for (int i = 0; i < dlen; i++) {
    if (decrypted[i] < 0x10) Serial.print("0");
    Serial.print(decrypted[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
  
  // === Verification ===
  Serial.println("\n--- Verification ---");
  if (decrypt_result == 0) {
    if (dlen == pt_len && memcmp(plaintext, decrypted, pt_len) == 0) {
      Serial.println("SUCCESS");
    } else {
      Serial.println("FAIL");
    }
  } else {
    Serial.println("FAILED Decryption");
  }
  
  // === Tampering Test ===
  Serial.println("\n--- Tampering Test ---");
  ciphertext[0] ^= 0x01;  // Flip one bit
  decrypt_result = crypto_aead_decrypt(
    decrypted, &dlen,
    NULL,
    ciphertext, clen,
    ad, ad_len,
    nonce,
    ASCON_KEY
  );
  
  if (decrypt_result != 0) {
    Serial.print("Tampering detected (returned ");
    Serial.print(decrypt_result);
    Serial.println(")");
  } else {
    Serial.println("Tampering not detected");
  }
  
  Serial.println("\n---");
  Serial.println("Test Completed");
  Serial.println("---");
  
  // === Send Test Results to Laptop ===
  if (wifiConnected) {
    digitalWrite(LED_PIN, HIGH);
    delay(100);
    digitalWrite(LED_PIN, LOW);
    
    // Build JSON payload with test results
    char jsonPayload[512];
    snprintf(jsonPayload, sizeof(jsonPayload),
      "{\"test\":\"Ascon AEAD\",\"encryption_result\":%d,\"decryption_result\":%d,"
      "\"ciphertext_len\":%d,\"plaintext_len\":%d,\"tamper_detected\":%s}",
      encrypt_result, decrypt_result, (int)clen, (int)pt_len,
      decrypt_result != 0 ? "true" : "false"
    );
    
    Serial.println("\nSending test results to Server...");
    sendDataToLaptop(jsonPayload);
  }
}

// ===========================
// Arduino Loop
// ===========================

void loop() {
  // Check if 10 seconds have passed
  unsigned long currentTime = millis();
  
  if (currentTime - lastTempTime >= TEMP_INTERVAL) {
    lastTempTime = currentTime;
    messageNonce++;
    
    // Flash LED to indicate data transmission
    digitalWrite(LED_PIN, HIGH);
    delay(100);
    digitalWrite(LED_PIN, LOW);
    delay(100);
    digitalWrite(LED_PIN, HIGH);
    delay(100);
    digitalWrite(LED_PIN, LOW);
    
    // Read DHT sensor (temperature + humidity)
    float temperature = dht.readTemperature();
    float humidity = dht.readHumidity();

    if (isnan(temperature) || isnan(humidity)) {
      Serial.println("Failed to read DHT sensor | Skipping send.");
      delay(1000);
      lastTempTime = currentTime;
      goto LOOP_END;
    }

    // Display sensor data
    Serial.print("[");
    Serial.print(currentTime / 1000);
    Serial.print("s] Temperature: ");
    Serial.print(temperature, 2);
    Serial.print(" °C, Humidity: ");
    Serial.print(humidity, 2);
    Serial.println(" %");

    // Build JSON payload including device id (MAC), temperature and humidity
    // Get MAC address
    uint8_t macaddr[6];
    esp_read_mac(macaddr, ESP_MAC_WIFI_STA);
    char macbuf[18];
    snprintf(macbuf, sizeof(macbuf), "%02X:%02X:%02X:%02X:%02X:%02X",
      macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);

    if (wifiConnected) {
      char tempPayload[512];
      char hashBuffer[65];
      snprintf(tempPayload, sizeof(tempPayload),
        "{\"device_id\":\"%s\",\"type\":\"environment\",\"timestamp\":%ld,\"temperature\":%f,\"humidity\":%f,\"unit\":\"Celsius\",\"nonce\":%lu",
        macbuf, currentTime / 1000, temperature, humidity, messageNonce
      );

      calculateIntegrityHash(tempPayload, hashBuffer);

      char finalPayload[700];
      snprintf(finalPayload, sizeof(finalPayload),
        "%s,\"integrity_hash\":\"%s\"}",
        tempPayload, hashBuffer
      );

      // Encrypt payload with Ascon and send envelope
      char npubHex[CRYPTO_NPUBBYTES * 2 + 1];
      char ctHex[1200];
      if (encryptAsconPayload(finalPayload, npubHex, sizeof(npubHex), ctHex, sizeof(ctHex))) {
        char envelope[1400];
        snprintf(envelope, sizeof(envelope),
          "{\"algo\":\"ASCON-128A\",\"ct\":\"%s\",\"npub\":\"%s\"}",
          ctHex, npubHex
        );
        Serial.print("Ascon Ciphertext: ");
        Serial.println(ctHex);
        sendDataToLaptop(envelope);
      } else {
        Serial.println("Ascon encryption failed (buffer or crypto error)");
      }
    }
  }
  
  LOOP_END:
  delay(100);  // Small delay to prevent overwhelming the CPU
}
