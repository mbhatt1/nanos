/*
 * Authority Kernel - Ed25519 Signature Verification Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Ed25519 verification based on TweetNaCl (public domain).
 * This is a minimal, constant-time implementation suitable for
 * kernel use where no external crypto libraries are available.
 */

#include "ak_ed25519.h"
#include "ak_compat.h"

/* ============================================================
 * TRUSTED KEYS STATE
 * ============================================================ */

static struct {
  heap h;
  u8 keys[AK_ED25519_MAX_TRUSTED_KEYS][AK_ED25519_PUBLIC_KEY_SIZE];
  const char *names[AK_ED25519_MAX_TRUSTED_KEYS];
  u32 count;
  boolean initialized;
} ed25519_state;

/* ============================================================
 * FIELD ARITHMETIC (mod 2^255 - 19)
 * ============================================================
 * All operations in constant time to prevent timing attacks.
 */

typedef s64 gf[16];

static const u8 __attribute__((unused)) _0[16] = {0};
static const u8 __attribute__((unused)) _9[32] = {9};

static const gf gf0 = {0};
static const gf gf1 = {1};
static const gf D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141,
                     0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
                     0xfe73, 0x2b6f, 0x6cee, 0x5203};
static const gf D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283,
                      0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
                      0xfce7, 0x56df, 0xd9dc, 0x2406};
static const gf X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525,
                     0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
                     0x53fe, 0xcd6e, 0x36d3, 0x2169};
static const gf Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                     0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                     0x6666, 0x6666, 0x6666, 0x6666};
static const gf I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f,
                     0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
                     0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static u64 L64(u64 x, int c) {
  return (x << c) | ((x & 0xffffffffffffffff) >> (64 - c));
}

static u32 __attribute__((unused)) ld32(const u8 *x) {
  u32 u = x[3];
  u = (u << 8) | x[2];
  u = (u << 8) | x[1];
  return (u << 8) | x[0];
}

static u64 dl64(const u8 *x) {
  u64 u = 0;
  for (int i = 0; i < 8; i++)
    u = (u << 8) | x[i];
  return u;
}

static void __attribute__((unused)) st32(u8 *x, u32 u) {
  for (int i = 0; i < 4; i++) {
    x[i] = u;
    u >>= 8;
  }
}

static void ts64(u8 *x, u64 u) {
  for (int i = 7; i >= 0; i--) {
    x[i] = u;
    u >>= 8;
  }
}

static int vn(const u8 *x, const u8 *y, int n) {
  u32 d = 0;
  for (int i = 0; i < n; i++)
    d |= x[i] ^ y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

static void set25519(gf r, const gf a) {
  for (int i = 0; i < 16; i++)
    r[i] = a[i];
}

static void car25519(gf o) {
  s64 c;
  for (int i = 0; i < 16; i++) {
    o[i] += (1LL << 16);
    c = o[i] >> 16;
    o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
    o[i] -= c << 16;
  }
}

static void sel25519(gf p, gf q, int b) {
  s64 t, c = ~(b - 1);
  for (int i = 0; i < 16; i++) {
    t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

static void pack25519(u8 *o, const gf n) {
  int b;
  gf m, t;
  set25519(t, n);
  car25519(t);
  car25519(t);
  car25519(t);
  for (int j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (int i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    b = (m[15] >> 16) & 1;
    m[14] &= 0xffff;
    sel25519(t, m, 1 - b);
  }
  for (int i = 0; i < 16; i++) {
    o[2 * i] = t[i] & 0xff;
    o[2 * i + 1] = t[i] >> 8;
  }
}

static int neq25519(const gf a, const gf b) {
  u8 c[32], d[32];
  pack25519(c, a);
  pack25519(d, b);
  return vn(c, d, 32);
}

static u8 par25519(const gf a) {
  u8 d[32];
  pack25519(d, a);
  return d[0] & 1;
}

static void unpack25519(gf o, const u8 *n) {
  for (int i = 0; i < 16; i++)
    o[i] = n[2 * i] + ((s64)n[2 * i + 1] << 8);
  o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; i++)
    o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; i++)
    o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b) {
  s64 t[31];
  for (int i = 0; i < 31; i++)
    t[i] = 0;
  for (int i = 0; i < 16; i++)
    for (int j = 0; j < 16; j++)
      t[i + j] += a[i] * b[j];
  for (int i = 0; i < 15; i++)
    t[i] += 38 * t[i + 16];
  for (int i = 0; i < 16; i++)
    o[i] = t[i];
  car25519(o);
  car25519(o);
}

static void S(gf o, const gf a) { M(o, a, a); }

static void inv25519(gf o, const gf i) {
  gf c;
  set25519(c, i);
  for (int a = 253; a >= 0; a--) {
    S(c, c);
    if (a != 2 && a != 4)
      M(c, c, i);
  }
  set25519(o, c);
}

static void pow2523(gf o, const gf i) {
  gf c;
  set25519(c, i);
  for (int a = 250; a >= 0; a--) {
    S(c, c);
    if (a != 1)
      M(c, c, i);
  }
  set25519(o, c);
}

/* ============================================================
 * SHA-512 (needed for Ed25519)
 * ============================================================ */

static u64 K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static void hashblock(u64 *x, const u8 *m) {
  u64 a, b, c, d, e, f, g, h;
  u64 w[80];

  for (int i = 0; i < 16; i++)
    w[i] = dl64(m + 8 * i);
  for (int i = 16; i < 80; i++) {
    u64 s0 = L64(w[i - 15], 63) ^ L64(w[i - 15], 56) ^ (w[i - 15] >> 7);
    u64 s1 = L64(w[i - 2], 45) ^ L64(w[i - 2], 3) ^ (w[i - 2] >> 6);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  a = x[0];
  b = x[1];
  c = x[2];
  d = x[3];
  e = x[4];
  f = x[5];
  g = x[6];
  h = x[7];

  for (int i = 0; i < 80; i++) {
    u64 S1 = L64(e, 50) ^ L64(e, 46) ^ L64(e, 23);
    u64 ch = (e & f) ^ (~e & g);
    u64 temp1 = h + S1 + ch + K[i] + w[i];
    u64 S0 = L64(a, 36) ^ L64(a, 30) ^ L64(a, 25);
    u64 maj = (a & b) ^ (a & c) ^ (b & c);
    u64 temp2 = S0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  x[0] += a;
  x[1] += b;
  x[2] += c;
  x[3] += d;
  x[4] += e;
  x[5] += f;
  x[6] += g;
  x[7] += h;
}

static int crypto_hash(u8 *out, const u8 *m, u64 n) {
  u64 x[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
              0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
              0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
              0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
  u8 b[128];
  u64 i, left = n & 127;

  for (i = 0; i + 128 <= n; i += 128)
    hashblock(x, m + i);

  runtime_memset(b, 0, 128);
  for (i = 0; i < left; i++)
    b[i] = m[n - left + i];
  b[left] = 0x80;

  if (left >= 112) {
    hashblock(x, b);
    runtime_memset(b, 0, 128);
  }
  ts64(b + 120, n << 3);
  hashblock(x, b);

  for (i = 0; i < 8; i++)
    ts64(out + 8 * i, x[i]);
  return 0;
}

/* ============================================================
 * ED25519 CURVE OPERATIONS
 * ============================================================ */

static void add(gf p[4], gf q[4]) {
  gf a, b, c, d, t, e, f, g, h;
  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

static void cswap(gf p[4], gf q[4], u8 b) {
  for (int i = 0; i < 4; i++)
    sel25519(p[i], q[i], b);
}

static void pack(u8 *r, gf p[4]) {
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

static void scalarmult(gf p[4], gf q[4], const u8 *s) {
  set25519(p[0], gf0);
  set25519(p[1], gf1);
  set25519(p[2], gf1);
  set25519(p[3], gf0);
  for (int i = 255; i >= 0; i--) {
    u8 b = (s[i / 8] >> (i & 7)) & 1;
    cswap(p, q, b);
    add(q, p);
    add(p, p);
    cswap(p, q, b);
  }
}

static void scalarbase(gf p[4], const u8 *s) {
  gf q[4];
  set25519(q[0], X);
  set25519(q[1], Y);
  set25519(q[2], gf1);
  M(q[3], X, Y);
  scalarmult(p, q, s);
}

static const u64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                          0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                          0,    0,    0,    0,    0,    0,    0,    0,
                          0,    0,    0,    0,    0,    0,    0,    0x10};

static void modL(u8 *r, s64 x[64]) {
  s64 carry;
  for (int i = 63; i >= 32; i--) {
    carry = 0;
    for (int j = i - 32; j < i - 12; j++) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[i - 12] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (int j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (int j = 0; j < 32; j++)
    x[j] -= carry * L[j];
  for (int i = 0; i < 32; i++) {
    x[i + 1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

static void reduce(u8 *r) {
  s64 x[64];
  for (int i = 0; i < 64; i++)
    x[i] = (u64)r[i];
  for (int i = 0; i < 64; i++)
    r[i] = 0;
  modL(r, x);
}

static int unpackneg(gf r[4], const u8 p[32]) {
  gf t, chk, num, den, den2, den4, den6;
  set25519(r[2], gf1);
  unpack25519(r[1], p);
  S(num, r[1]);
  M(den, num, D);
  Z(num, num, r[2]);
  A(den, r[2], den);

  S(den2, den);
  S(den4, den2);
  M(den6, den4, den2);
  M(t, den6, num);
  M(t, t, den);

  pow2523(t, t);
  M(t, t, num);
  M(t, t, den);
  M(t, t, den);
  M(r[0], t, den);

  S(chk, r[0]);
  M(chk, chk, den);
  if (neq25519(chk, num))
    M(r[0], r[0], I);

  S(chk, r[0]);
  M(chk, chk, den);
  if (neq25519(chk, num))
    return -1;

  if (par25519(r[0]) == (p[31] >> 7))
    Z(r[0], gf0, r[0]);

  M(r[3], r[0], r[1]);
  return 0;
}

/* ============================================================
 * PUBLIC API
 * ============================================================ */

void ak_ed25519_init(heap h) {
  ed25519_state.h = h;
  ed25519_state.count = 0;
  ed25519_state.initialized = true;
  runtime_memset((u8 *)ed25519_state.keys, 0, sizeof(ed25519_state.keys));
  runtime_memset((u8 *)ed25519_state.names, 0, sizeof(ed25519_state.names));
}

boolean ak_ed25519_verify(const u8 *message, u64 message_len,
                          const u8 *signature, const u8 *public_key) {
  u8 t[32], h[64];
  gf p[4], q[4];

  /* Verify heap is initialized */
  if (!ed25519_state.initialized || !ed25519_state.h)
    return false;

  if (!message || !signature || !public_key)
    return false;

  /* Overflow check: message_len + 64 */
  if (message_len > UINT64_MAX - 64)
    return false;

  if (unpackneg(q, public_key))
    return false;

  /* Hash R || pk || m */
  u8 *sm = allocate(ed25519_state.h, message_len + 64);
  if (!sm || sm == INVALID_ADDRESS)
    return false;

  runtime_memcpy(sm, signature, 32);             /* R */
  runtime_memcpy(sm + 32, public_key, 32);       /* pk */
  runtime_memcpy(sm + 64, message, message_len); /* m */

  crypto_hash(h, sm, message_len + 64);
  reduce(h);

  /* Compute R' = sB - hA */
  scalarmult(p, q, h);
  scalarbase(q, signature + 32);
  add(p, q);
  pack(t, p);

  deallocate(ed25519_state.h, sm, message_len + 64);

  /* Verify R == R' */
  return vn(signature, t, 32) == 0;
}

boolean ak_ed25519_add_trusted_key(const u8 *public_key, const char *name) {
  if (!ed25519_state.initialized)
    return false;

  if (!public_key)
    return false;

  if (ed25519_state.count >= AK_ED25519_MAX_TRUSTED_KEYS)
    return false;

  /* Check for duplicate */
  for (u32 i = 0; i < ed25519_state.count; i++) {
    if (runtime_memcmp(ed25519_state.keys[i], public_key,
                       AK_ED25519_PUBLIC_KEY_SIZE) == 0)
      return true; /* Already exists */
  }

  runtime_memcpy(ed25519_state.keys[ed25519_state.count], public_key,
                 AK_ED25519_PUBLIC_KEY_SIZE);
  ed25519_state.names[ed25519_state.count] = name;
  ed25519_state.count++;
  return true;
}

boolean ak_ed25519_is_trusted(const u8 *public_key) {
  if (!ed25519_state.initialized || !public_key)
    return false;

  for (u32 i = 0; i < ed25519_state.count; i++) {
    if (runtime_memcmp(ed25519_state.keys[i], public_key,
                       AK_ED25519_PUBLIC_KEY_SIZE) == 0)
      return true;
  }
  return false;
}

boolean ak_ed25519_remove_trusted_key(const u8 *public_key) {
  if (!ed25519_state.initialized || !public_key)
    return false;

  for (u32 i = 0; i < ed25519_state.count; i++) {
    if (runtime_memcmp(ed25519_state.keys[i], public_key,
                       AK_ED25519_PUBLIC_KEY_SIZE) == 0) {
      /* Move last key to this slot */
      if (i < ed25519_state.count - 1) {
        runtime_memcpy(ed25519_state.keys[i],
                       ed25519_state.keys[ed25519_state.count - 1],
                       AK_ED25519_PUBLIC_KEY_SIZE);
        ed25519_state.names[i] = ed25519_state.names[ed25519_state.count - 1];
      }
      ed25519_state.count--;
      return true;
    }
  }
  return false;
}

u32 ak_ed25519_trusted_key_count(void) { return ed25519_state.count; }
