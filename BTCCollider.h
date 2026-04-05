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

#ifndef BTCCOLLIDERH
#define BTCCOLLIDERH

#include <string>
#include <vector>
#include "SECP256k1.h"
#include "HashTable.h"
#include "IntGroup.h"
#include "GPU/GPUEngine.h"

#ifdef WIN64
#include <Windows.h>
#endif

class BTCCollider;

typedef struct {

  BTCCollider *obj;
  int  threadId;
  bool isRunning;
  bool hasStarted;
  bool isWaiting;
  Int  localSeed;
  hash160_t start;
  hash160_t end;
  uint64_t nbWalk;
  hash160_t *x;  // Starting path item
  hash160_t *y;  // Current path item

#ifdef WITHGPU
  int gridSizeX;
  int gridSizeY;
  int gpuId;
  GPUEngine *gpu;
#endif

} TH_PARAM;

#ifdef WIN64
typedef HANDLE THREAD_HANDLE;
#else
typedef pthread_t THREAD_HANDLE;
#endif

#define CPU_AFFINE

#define HASHOK(h) (((h).i8[0] & 0x80)==0)
#define PUBX(i,j) pub[(i)*(65536*2) + 2*(j)]
#define PUBY(i,j) pub[(i)*(65536*2) + 2*(j)+1]

class BTCCollider {

public:
  BTCCollider(Secp256K1 *secp, bool useGpu, bool stop, std::string outputFile,
              std::string workFile, std::string iWorkFile, uint32_t savePeriod,
              uint32_t n, int dp, bool extraPoint,
              std::string targetPrefix, std::string rangeStart, std::string rangeEnd);

  void Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize);
  void Check(std::vector<int> gpuId, std::vector<int> gridSize);

  void FindCollisionCPU(TH_PARAM *p);
  void FindCollisionGPU(TH_PARAM *p);
  void UndistinguishCPU(TH_PARAM *p);
  void InitKey(TH_PARAM *p);

private:

  Int  GetPrivKey(hash160_t x);
  hash160_t F(hash160_t x);
  bool IsDP(hash160_t x);
  bool IsEqual(hash160_t x1, hash160_t x2);
  void SetDP(int size);
  void FGroup(IntGroup *grp, Point *pts, Int *di, hash160_t *x);
  void AddGroup(IntGroup *grp, hash160_t *x, Point *p1, Int *dx, int i, uint16_t colMask);
  void Lock();
  void Unlock();
  void SaveWork(uint64_t totalCount, double totalTime, TH_PARAM *threads, int nbThread);
  void LoadWork(std::string &fileName);

  // ---- New: prefix filter and key range ----
  bool MatchesPrefix(hash160_t *h);
  Int  ClampKey(Int &key);           // Clamp key into [rangeStart, rangeEnd]
  void ParsePrefix(const std::string &hexPrefix);

  // Prefix filter data
  uint8_t  prefixBytes[20];          // Target prefix bytes (left-aligned in HASH160)
  int      prefixLength;             // Number of hex chars in prefix
  int      prefixBitLen;             // Number of bits to match (prefixLength * 4)
  bool     usePrefix;                // Whether prefix filtering is enabled

  // Key range
  Int      keyRangeStart;
  Int      keyRangeEnd;
  Int      keyRangeWidth;            // rangeEnd - rangeStart + 1

  // Original members
  Secp256K1 *secp;
  HashTable hashTable;
  uint64_t  counters[256];
  int       nbCPUThread;
  int       nbGPUThread;
  uint64_t  offsetCount;
  double    offsetTime;
  int       CPU_GRP_SIZE;
  bool      useGpu;
  bool      endOfSearch;
  bool      useSSE;
  bool      extraPoints;
  uint32_t  colSize;
  uint64_t  dpMask;
  int       dpSize;
  int       initDPSize;
  std::string outputFile;
  std::string workFile;
  uint32_t  saveWorkPeriod;
  std::string initialSeed;
  uint64_t  nbLoadedWalk;
  bool      saveRequest;

#ifdef WIN64
  HANDLE ghMutex;
#else
  pthread_mutex_t ghMutex;
#endif

};

#endif // BTCCOLLIDERH
