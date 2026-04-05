/*
 * This file is part of the BTCCollider distribution (https://github.com/JeanLucPons/BTCCollider).
 * Copyright (c) 2020 Jean Luc PONS.
 * Modified fork: prefix-targeted search with key range constraint.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "BTCCollider.h"
#include "Base58.h"
#include "Bech32.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <string.h>
#define _USE_MATH_DEFINES
#include <math.h>
#include <algorithm>
#ifndef WIN64
#include <pthread.h>
#endif

using namespace std;

// ============================================================================
// Thread entry points (unchanged from original)
// ============================================================================

#ifdef WIN64
DWORD WINAPI _InitKey(LPVOID lpParam) {
#else
void *_InitKey(void *lpParam) {
#endif
  TH_PARAM *p = (TH_PARAM *)lpParam;
  p->obj->InitKey(p);
  return 0;
}

#ifdef WIN64
DWORD WINAPI _FindCollisionCPU(LPVOID lpParam) {
#else
void *_FindCollisionCPU(void *lpParam) {
#endif
  TH_PARAM *p = (TH_PARAM *)lpParam;
  p->obj->FindCollisionCPU(p);
  return 0;
}

#ifdef WIN64
DWORD WINAPI _FindCollisionGPU(LPVOID lpParam) {
#else
void *_FindCollisionGPU(void *lpParam) {
#endif
  TH_PARAM *p = (TH_PARAM *)lpParam;
  p->obj->FindCollisionGPU(p);
  return 0;
}

#ifdef WIN64
DWORD WINAPI _UndistinguishCPU(LPVOID lpParam) {
#else
void *_UndistinguishCPU(void *lpParam) {
#endif
  TH_PARAM *p = (TH_PARAM *)lpParam;
  p->obj->UndistinguishCPU(p);
  return 0;
}

// ============================================================================
// Prefix parsing and matching (NEW)
// ============================================================================

void BTCCollider::ParsePrefix(const std::string &hexPrefix) {

  memset(prefixBytes, 0, 20);
  prefixLength = (int)hexPrefix.length();
  prefixBitLen = prefixLength * 4;
  usePrefix = (prefixLength > 0);

  if (!usePrefix) return;

  // Parse hex string into bytes (left-aligned in prefixBytes)
  for (int i = 0; i < prefixLength; i++) {
    uint8_t nibble;
    char c = hexPrefix[i];
    if (c >= '0' && c <= '9')      nibble = c - '0';
    else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
    else nibble = 0;

    int byteIdx = i / 2;
    if (i % 2 == 0)
      prefixBytes[byteIdx] |= (nibble << 4);
    else
      prefixBytes[byteIdx] |= nibble;
  }
}

bool BTCCollider::MatchesPrefix(hash160_t *h) {

  if (!usePrefix) return true;  // No filter => everything matches

  int fullBytes = prefixLength / 2;
  int remainNibble = prefixLength % 2;

  // Compare full bytes
  for (int i = 0; i < fullBytes; i++) {
    if (h->i8[i] != prefixBytes[i])
      return false;
  }

  // Compare remaining nibble (high nibble of next byte)
  if (remainNibble) {
    uint8_t mask = 0xF0;
    if ((h->i8[fullBytes] & mask) != (prefixBytes[fullBytes] & mask))
      return false;
  }

  return true;
}

// ============================================================================
// Key range clamping (NEW)
// ============================================================================

Int BTCCollider::ClampKey(Int &key) {

  // Clamp key into [keyRangeStart, keyRangeEnd]
  // Method: key = (key mod rangeWidth) + rangeStart
  Int result;
  result.Set(&key);

  // Make positive
  if (result.IsNegative())
    result.Neg();

  // Modulo rangeWidth
  result.Mod(&keyRangeWidth);

  // Add rangeStart
  result.Add(&keyRangeStart);

  return result;
}

// ============================================================================
// Constructor (MODIFIED — accepts prefix and range)
// ============================================================================

BTCCollider::BTCCollider(Secp256K1 *secp, bool useGpu, bool stop, std::string outputFile,
                         std::string workFile, std::string iWorkFile, uint32_t savePeriod,
                         uint32_t n, int dp, bool extraPoints,
                         std::string targetPrefix, std::string rangeStart, std::string rangeEnd) {

  this->secp = secp;
  this->useGpu = useGpu;
  this->outputFile = outputFile;
  this->useSSE = true;
  this->nbGPUThread = 0;
  this->colSize = n;
  this->CPU_GRP_SIZE = 128;
  this->initDPSize = dp;
  this->extraPoints = extraPoints;
  this->workFile = workFile;
  this->saveWorkPeriod = savePeriod;
  this->endOfSearch = false;
  this->saveRequest = false;

  // Parse target prefix
  ParsePrefix(targetPrefix);
  if (usePrefix) {
    printf("Prefix filter: ");
    for (int i = 0; i < (prefixLength + 1) / 2; i++)
      printf("%02X", prefixBytes[i]);
    printf(" (%d bits)\n", prefixBitLen);
  }

  // Parse key range
  keyRangeStart.SetBase16(rangeStart.c_str());
  keyRangeEnd.SetBase16(rangeEnd.c_str());
  keyRangeWidth.Set(&keyRangeEnd);
  keyRangeWidth.Sub(&keyRangeStart);
  Int one;
  one.SetInt32(1);
  keyRangeWidth.Add(&one);

  printf("Key range start : 0x%s\n", keyRangeStart.GetBase16().c_str());
  printf("Key range end   : 0x%s\n", keyRangeEnd.GetBase16().c_str());
  printf("Key range width : 2^%.2f\n", log2((double)keyRangeWidth.IsNegative() ?
         1.0 : keyRangeWidth.IsZero() ? 1.0 :
         pow(2.0, keyRangeWidth.GetBitLength())));

  if (iWorkFile.length() > 0) {
    LoadWork(iWorkFile);
  } else {
    // Seed
    initialSeed = Timer::getSeed(32);
    offsetCount = 0;
    nbLoadedWalk = 0;
  }

  // Init mutex
#ifdef WIN64
  ghMutex = CreateMutex(NULL, FALSE, NULL);
#else
  ghMutex = PTHREAD_MUTEX_INITIALIZER;
#endif

}

// ============================================================================
// GetPrivKey (MODIFIED — clamps to range)
// ============================================================================

Int BTCCollider::GetPrivKey(hash160_t x) {

  // Derive a 256-bit integer from the HASH160
  Int key;
  key.SetInt32(0);

  // Use the 160 bits of HASH160 as seed material
  // Pack the 20 bytes into the Int
  for (int i = 0; i < 5; i++) {
    key.bits[i] = (uint32_t)x.i32[i];
  }

  // Clamp into [rangeStart, rangeEnd]
  return ClampKey(key);

}

// ============================================================================
// F function (MODIFIED — uses clamped key)
// ============================================================================

hash160_t BTCCollider::F(hash160_t x) {

  // Get private key in range
  Int privKey = GetPrivKey(x);

  // Compute public key
  Point pub = secp->ComputePublicKey(&privKey);

  // Compute HASH160 = RIPEMD160(SHA256(pubkey))
  unsigned char pubKeyBytes[33];
  secp->GetPubKeyBytes(true, pub, pubKeyBytes);  // compressed

  unsigned char sha[32];
  sha256(pubKeyBytes, 33, sha);

  hash160_t result;
  ripemd160(sha, 32, result.i8);

  return result;

}

// ============================================================================
// Distinguished Point methods (unchanged logic)
// ============================================================================

bool BTCCollider::IsDP(hash160_t x) {
  return (x.i64[0] & dpMask) == 0;
}

bool BTCCollider::IsEqual(hash160_t x1, hash160_t x2) {
  return (x1.i64[0] == x2.i64[0]) &&
         (x1.i64[1] == x2.i64[1]) &&
         (x1.i32[4] == x2.i32[4]);
}

void BTCCollider::SetDP(int size) {
  dpSize = size;
  dpMask = (1ULL << (uint64_t)size) - 1;
  dpMask = dpMask << (64 - size);
  printf("DP size: %d [0x%016llX]\n", dpSize, (unsigned long long)dpMask);
}

// ============================================================================
// Lock / Unlock (unchanged)
// ============================================================================

void BTCCollider::Lock() {
#ifdef WIN64
  WaitForSingleObject(ghMutex, INFINITE);
#else
  pthread_mutex_lock(&ghMutex);
#endif
}

void BTCCollider::Unlock() {
#ifdef WIN64
  ReleaseMutex(ghMutex);
#else
  pthread_mutex_unlock(&ghMutex);
#endif
}

// ============================================================================
// InitKey (MODIFIED — generates starting keys within range)
// ============================================================================

void BTCCollider::InitKey(TH_PARAM *p) {

  // Generate a random starting key within [rangeStart, rangeEnd]
  Int randKey;
  randKey.Rand(&keyRangeWidth);
  randKey.Add(&keyRangeStart);

  // Compute the HASH160 of this starting key
  Point pub = secp->ComputePublicKey(&randKey);
  unsigned char pubKeyBytes[33];
  secp->GetPubKeyBytes(true, pub, pubKeyBytes);

  unsigned char sha[32];
  sha256(pubKeyBytes, 33, sha);

  ripemd160(sha, 32, p->x[0].i8);
  p->y[0] = p->x[0];

  p->hasStarted = true;

}

// ============================================================================
// FindCollisionCPU (MODIFIED — adds prefix check before hash table insert)
// ============================================================================

void BTCCollider::FindCollisionCPU(TH_PARAM *p) {

  p->hasStarted = true;

  // Collision search loop
  while (!endOfSearch) {

    // Iterate the walk
    hash160_t h = F(p->y[0]);
    p->y[0] = h;
    counters[p->threadId]++;

    // Check if this is a Distinguished Point
    if (IsDP(h)) {

      // NEW: Check prefix match before storing
      if (usePrefix && !MatchesPrefix(&h)) {
        // DP doesn't match prefix — restart walk with new random key
        Int randKey;
        randKey.Rand(&keyRangeWidth);
        randKey.Add(&keyRangeStart);

        Point pub = secp->ComputePublicKey(&randKey);
        unsigned char pubKeyBytes[33];
        secp->GetPubKeyBytes(true, pub, pubKeyBytes);
        unsigned char sha[32];
        sha256(pubKeyBytes, 33, sha);
        ripemd160(sha, 32, p->y[0].i8);
        p->x[0] = p->y[0];
        continue;
      }

      Lock();

      int r = hashTable.AddHash(&(p->x[0]), &h);

      if (r == COLLISION) {

        // Collision found!
        hash160_t colA, colB, colEnd;
        hashTable.getCollision(&colA, &colB, &colEnd);

        // Print results
        Int privA = GetPrivKey(colA);
        Int privB = GetPrivKey(colB);

        Point pubA = secp->ComputePublicKey(&privA);
        Point pubB = secp->ComputePublicKey(&privB);

        string addrA = secp->GetAddress(0, true, pubA);  // P2PKH compressed
        string addrB = secp->GetAddress(0, true, pubB);

        printf("\n[Prefix Match Found!]\n");
        printf("H1=%s\n", hashTable.GetHashStr(&colA).c_str());
        printf("H2=%s\n", hashTable.GetHashStr(&colB).c_str());
        printf("Priv (WIF): p2pkh:%s\n", secp->GetPrivAddress(true, privA).c_str());
        printf("Priv (WIF): p2pkh:%s\n", secp->GetPrivAddress(true, privB).c_str());
        printf("Priv (HEX): %s\n", privA.GetBase16().c_str());
        printf("Priv (HEX): %s\n", privB.GetBase16().c_str());
        printf("Add1: %s\n", addrA.c_str());
        printf("Add2: %s\n", addrB.c_str());

        // Write to output file
        if (outputFile.length() > 0) {
          FILE *f = fopen(outputFile.c_str(), "a");
          if (f) {
            fprintf(f, "H1=%s\n", hashTable.GetHashStr(&colA).c_str());
            fprintf(f, "H2=%s\n", hashTable.GetHashStr(&colB).c_str());
            fprintf(f, "Priv1 (HEX): %s\n", privA.GetBase16().c_str());
            fprintf(f, "Priv2 (HEX): %s\n", privB.GetBase16().c_str());
            fprintf(f, "Add1: %s\n", addrA.c_str());
            fprintf(f, "Add2: %s\n\n", addrB.c_str());
            fclose(f);
          }
        }

        endOfSearch = true;
      }

      Unlock();

      // Start a new walk from a fresh random key in range
      Int randKey;
      randKey.Rand(&keyRangeWidth);
      randKey.Add(&keyRangeStart);
      Point pub = secp->ComputePublicKey(&randKey);
      unsigned char pubKeyBytes[33];
      secp->GetPubKeyBytes(true, pub, pubKeyBytes);
      unsigned char sha[32];
      sha256(pubKeyBytes, 33, sha);
      ripemd160(sha, 32, p->y[0].i8);
      p->x[0] = p->y[0];
    }

  }

  p->isRunning = false;

}

// ============================================================================
// FindCollisionGPU (MODIFIED — adds prefix check)
// ============================================================================

void BTCCollider::FindCollisionGPU(TH_PARAM *p) {

#ifdef WITHGPU
  p->hasStarted = true;

  // GPU implementation would follow the same pattern:
  // 1. GPU kernel runs F() iterations with clamped keys
  // 2. GPU reports back DPs
  // 3. CPU filters DPs by prefix match
  // 4. Matching DPs get inserted into hash table
  //
  // The GPU kernel (GPUEngine.cu) needs modification to:
  // - Accept rangeStart, rangeWidth as device constants
  // - Clamp derived keys: key = (hash_bits mod rangeWidth) + rangeStart
  // - Optionally do prefix check on-device to reduce PCIe traffic
  //
  // For now, this is a placeholder that falls through to CPU.
  // Full GPU implementation requires modifying GPUEngine.cu (CUDA kernel).

  printf("GPU thread %d: GPU kernel needs CUDA modifications for range clamping.\n", p->threadId);
  printf("Falling back to CPU for this thread.\n");

  FindCollisionCPU(p);

#endif

  p->isRunning = false;
}

// ============================================================================
// UndistinguishCPU (MODIFIED — uses clamped keys)
// ============================================================================

void BTCCollider::UndistinguishCPU(TH_PARAM *p) {

  p->hasStarted = true;

  // Retrace walk from start to find exact collision point
  hash160_t current = p->start;
  while (!IsEqual(current, p->end)) {
    hash160_t next = F(current);
    if (IsEqual(next, p->end)) {
      p->end = current;
      break;
    }
    current = next;
    counters[p->threadId]++;
  }

  p->isRunning = false;

}

// ============================================================================
// Search (MODIFIED — adjusted DP calculation and status display)
// ============================================================================

void BTCCollider::Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize) {

  double t0 = Timer::get_tick();
  nbCPUThread = nbThread;
  endOfSearch = false;

  // Compute optimal DP based on range size, not full 160-bit space
  int rangeBits = keyRangeWidth.GetBitLength();
  int totalRW = nbCPUThread;
#ifdef WITHGPU
  for (size_t i = 0; i < gpuId.size(); i++)
    totalRW += gridSize[2 * i] * gridSize[2 * i + 1];
#endif
  if (totalRW < 1) totalRW = 1;

  if (initDPSize < 0) {
    int optimalDP;
    if (usePrefix) {
      // For prefix search: DP should be smaller since we're not doing birthday attack
      optimalDP = std::max(1, (int)((double)prefixBitLen / 2.0 - log2((double)totalRW) - 2));
    } else {
      optimalDP = (int)((double)colSize / 2.0 - log2((double)totalRW) - 2);
    }
    if (optimalDP < 0) optimalDP = 0;
    SetDP(optimalDP);
  } else {
    SetDP(initDPSize);
  }

  int nb = colSize / 2;
  int nbFull = nb / 16;
  uint16_t colMask = (1 << (nb % 16)) - 1;
  hashTable.SetParam(colSize, nbFull, colMask);

  printf("Collision: %d bits\n", colSize);
  printf("Seed: %s\n", initialSeed.c_str());
  printf("Number of CPU thread: %d\n", nbCPUThread);

  printf("Initializing keys...\n");

  // Allocate threads
  int totalThread = nbCPUThread;
  TH_PARAM *params = new TH_PARAM[totalThread];
  THREAD_HANDLE *threads = new THREAD_HANDLE[totalThread];
  memset(counters, 0, sizeof(counters));

  for (int i = 0; i < totalThread; i++) {
    params[i].obj = this;
    params[i].threadId = i;
    params[i].isRunning = true;
    params[i].hasStarted = false;
    params[i].isWaiting = false;
    params[i].nbWalk = 1;
    params[i].x = new hash160_t[1];
    params[i].y = new hash160_t[1];

    // Initialize starting key
    InitKey(&params[i]);
  }

  printf("Starting search...\n");

  // Launch CPU threads
  for (int i = 0; i < nbCPUThread; i++) {
#ifdef WIN64
    threads[i] = CreateThread(NULL, 0, _FindCollisionCPU, (void *)(params + i), 0, NULL);
    if (threads[i] == NULL) {
      printf("Error creating thread %d\n", i);
      exit(-1);
    }
#else
    int ret = pthread_create(&threads[i], NULL, _FindCollisionCPU, (void *)(params + i));
    if (ret) {
      printf("Error creating thread %d: %d\n", i, ret);
      exit(-1);
    }
#endif
  }

  // Status display loop
  uint64_t lastCount = 0;
  double lastTime = t0;
  double startTime = t0;

  while (!endOfSearch) {

    Timer::SleepMillis(2000);

    uint64_t totalCount = offsetCount;
    for (int i = 0; i < totalThread; i++)
      totalCount += counters[i];

    double now = Timer::get_tick();
    double elapsed = now - startTime;
    double speed = (double)(totalCount - lastCount) / (now - lastTime);

    char timeStr[128];
    Timer::printResult(timeStr, 128, elapsed);

    printf("\r[%.1f Mips][Cnt 2^%.2f][T %s][hSize %.1fMB]   ",
           speed / 1e6,
           totalCount > 0 ? log2((double)totalCount) : 0.0,
           timeStr,
           hashTable.GetSizeMB());
    fflush(stdout);

    lastCount = totalCount;
    lastTime = now;

    // Save work periodically
    if (workFile.length() > 0 && saveRequest) {
      SaveWork(totalCount, elapsed, params, totalThread);
      saveRequest = false;
    }

  }

  // Wait for threads to finish
  for (int i = 0; i < nbCPUThread; i++) {
#ifdef WIN64
    WaitForSingleObject(threads[i], INFINITE);
    CloseHandle(threads[i]);
#else
    pthread_join(threads[i], NULL);
#endif
  }

  // Cleanup
  for (int i = 0; i < totalThread; i++) {
    delete[] params[i].x;
    delete[] params[i].y;
  }
  delete[] params;
  delete[] threads;

  double totalTime = Timer::get_tick() - t0;
  char timeStr[128];
  Timer::printResult(timeStr, 128, totalTime);
  printf("\nTotal time: %s\n", timeStr);

}

// ============================================================================
// Check (mostly unchanged)
// ============================================================================

void BTCCollider::Check(std::vector<int> gpuId, std::vector<int> gridSize) {

  printf("Checking F function...\n");

  // Generate a test key in range
  Int testKey;
  testKey.Rand(&keyRangeWidth);
  testKey.Add(&keyRangeStart);
  printf("Test key: 0x%s\n", testKey.GetBase16().c_str());

  // Compute its HASH160
  Point pub = secp->ComputePublicKey(&testKey);
  unsigned char pubKeyBytes[33];
  secp->GetPubKeyBytes(true, pub, pubKeyBytes);
  unsigned char sha[32];
  sha256(pubKeyBytes, 33, sha);
  hash160_t h;
  ripemd160(sha, 32, h.i8);

  printf("HASH160: ");
  for (int i = 0; i < 20; i++) printf("%02X", h.i8[i]);
  printf("\n");

  // Test F function
  hash160_t h2 = F(h);
  printf("F(h)   : ");
  for (int i = 0; i < 20; i++) printf("%02X", h2.i8[i]);
  printf("\n");

  // Verify derived key is in range
  Int derived = GetPrivKey(h);
  printf("Derived key: 0x%s\n", derived.GetBase16().c_str());

  bool inRange = (derived.IsGreaterOrEqual(&keyRangeStart) &&
                  keyRangeEnd.IsGreaterOrEqual(&derived));
  printf("In range: %s\n", inRange ? "YES" : "NO");

  // Test prefix match
  if (usePrefix) {
    printf("Prefix match: %s\n", MatchesPrefix(&h) ? "YES" : "NO");
    printf("F(h) prefix match: %s\n", MatchesPrefix(&h2) ? "YES" : "NO");
  }

  printf("Check done.\n");
}

// ============================================================================
// SaveWork / LoadWork (simplified for fork)
// ============================================================================

void BTCCollider::SaveWork(uint64_t totalCount, double totalTime,
                           TH_PARAM *threads, int nbThread) {

  FILE *f = fopen(workFile.c_str(), "wb");
  if (!f) {
    printf("Cannot save work file %s\n", workFile.c_str());
    return;
  }

  fwrite(&totalCount, sizeof(uint64_t), 1, f);
  fwrite(&totalTime, sizeof(double), 1, f);

  // Save hash table
  hashTable.SaveTable(f);

  fclose(f);
  printf("\nWork saved to %s\n", workFile.c_str());

}

void BTCCollider::LoadWork(std::string &fileName) {

  FILE *f = fopen(fileName.c_str(), "rb");
  if (!f) {
    printf("Cannot load work file %s\n", fileName.c_str());
    exit(-1);
  }

  fread(&offsetCount, sizeof(uint64_t), 1, f);
  double savedTime;
  fread(&savedTime, sizeof(double), 1, f);
  offsetTime = savedTime;

  // Load hash table
  hashTable.LoadTable(f);

  fclose(f);

  initialSeed = Timer::getSeed(32);
  nbLoadedWalk = 0;

  printf("Loaded work from %s (count=2^%.2f)\n", fileName.c_str(),
         offsetCount > 0 ? log2((double)offsetCount) : 0.0);

}
