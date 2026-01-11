#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "api.h"

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

static int hex2bytes(const char *hex, unsigned char *out, size_t out_len) {
  size_t len = strlen(hex);
  if (len % 2 != 0) return -1;
  if (out_len < len / 2) return -1;
  for (size_t i = 0; i < len / 2; ++i) {
    unsigned int val;
    if (sscanf(&hex[2 * i], "%2x", &val) != 1) return -1;
    out[i] = (unsigned char)val;
  }
  return (int)(len / 2);
}

static void usage(const char *prog) {
  fprintf(stderr, "Usage: %s enc|dec <key_hex> <npub_hex> <data_hex> [ad_hex]\n", prog);
}

int main(int argc, char **argv) {
  if (argc < 5) {
    usage(argv[0]);
    return 1;
  }

  const char *mode = argv[1];
  const char *key_hex = argv[2];
  const char *npub_hex = argv[3];
  const char *data_hex = argv[4];
  const char *ad_hex = (argc >= 6) ? argv[5] : "";

  unsigned char key[CRYPTO_KEYBYTES];
  unsigned char npub[CRYPTO_NPUBBYTES];
  unsigned char ad_buf[512];

  int key_len = hex2bytes(key_hex, key, sizeof(key));
  int npub_len = hex2bytes(npub_hex, npub, sizeof(npub));
  int ad_len = hex2bytes(ad_hex, ad_buf, sizeof(ad_buf));
  if (key_len != CRYPTO_KEYBYTES || npub_len != CRYPTO_NPUBBYTES || ad_len < 0) {
    fprintf(stderr, "bad key/npub/ad length\n");
    return 1;
  }

  size_t data_bytes = strlen(data_hex) / 2;
  unsigned char *data = (unsigned char *)malloc(data_bytes > 0 ? data_bytes : 1);
  if (!data) {
    fprintf(stderr, "alloc failed\n");
    return 1;
  }
  if (hex2bytes(data_hex, data, data_bytes) != (int)data_bytes) {
    fprintf(stderr, "bad data hex\n");
    free(data);
    return 1;
  }

  if (strcmp(mode, "enc") == 0) {
    unsigned long long clen = data_bytes + CRYPTO_ABYTES;
    unsigned char *ct = (unsigned char *)malloc(clen);
    if (!ct) {
      fprintf(stderr, "alloc failed\n");
      free(data);
      return 1;
    }
    if (crypto_aead_encrypt(ct, &clen, data, data_bytes, ad_buf, ad_len, NULL, npub, key) != 0) {
      fprintf(stderr, "encrypt failed\n");
      free(data);
      free(ct);
      return 1;
    }
    for (unsigned long long i = 0; i < clen; ++i) printf("%02x", ct[i]);
    printf("\n");
    free(ct);
    free(data);
    return 0;
  }

  if (strcmp(mode, "dec") == 0) {
    if (data_bytes < CRYPTO_ABYTES) {
      fprintf(stderr, "ciphertext too short\n");
      free(data);
      return 1;
    }
    unsigned long long mlen = data_bytes - CRYPTO_ABYTES;
    unsigned char *pt = (unsigned char *)malloc(mlen + 1);
    if (!pt) {
      fprintf(stderr, "alloc failed\n");
      free(data);
      return 1;
    }
    int rc = crypto_aead_decrypt(pt, &mlen, NULL, data, data_bytes, ad_buf, ad_len, npub, key);
    if (rc != 0) {
      fprintf(stderr, "decrypt failed\n");
      free(pt);
      free(data);
      return 2;
    }
    pt[mlen] = '\0';
    fwrite(pt, 1, mlen, stdout);
    printf("\n");
    free(pt);
    free(data);
    return 0;
  }

  usage(argv[0]);
  free(data);
  return 1;
}
