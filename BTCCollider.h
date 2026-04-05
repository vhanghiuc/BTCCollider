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
#define _byteswap_uint64 _byteswap_uint64
#else
typedef pthread_t THREAD_HANDLE;
#define _byteswap_uint64 __builtin_bswap64
#endif

#define CPU_AFFINE

//#define STATISTICS

#define HASHOK(h) (((h).i8[0] & 0x80)==0)
#define PUBX(i,j) pub[(i)*(65536*2) + 2*(j)]
#define PUBY(i,j) pub[(i)*(65536*2) + 2*(j)+1]

class BTCCollider {

public:
  // MODIFIED: Constructor accepts prefix and range parameters
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

  // Original methods
  Int  GetPrivKey(hash160_t x);
  hash160_t F(hash160_t x);
  bool IsDP(hash160_t x);
  bool IsEqual(hash160_t x1, hash160_t x2);
  void SetDP(int size);
  void FGroup(IntGroup *grp, Point *pts, Int *di, hash160_t *x);
  void AddGroup(IntGroup *grp, hash160_t *x, Point *p1, Int *dx, int i, uint16_t colMask);
  Point Add(Point &p1, int n, uint16_t h);
  void Lock();
  void Unlock();
  void SaveWork(uint64_t totalCount, double totalTime, TH_PARAM *threads, int nbThread);
  void LoadWork(std::string fileName);
  void FetchWalks(hash160_t *x, hash160_t *y, uint64_t nbWalk);
  void Rand(Int *seed, Int *i);
  void Rand(Int *seed, hash160_t *i);
  std::string GetHex(hash160_t x);
  std::string GetTimeStr(double dTime);
  bool isAlive(TH_PARAM *p);
  bool hasStarted(TH_PARAM *p);
  bool isWaiting(TH_PARAM *p);
  uint64_t getGPUCount();
  uint64_t getCPUCount();

#ifdef WIN64
  THREAD_HANDLE LaunchThread(LPTHREAD_START_ROUTINE func, TH_PARAM *p);
#else
  THREAD_HANDLE LaunchThread(void *(*func)(void *), TH_PARAM *p);
#endif
  void JoinThreads(THREAD_HANDLE *handles, int nbThread);
  void FreeHandles(THREAD_HANDLE *handles, int nbThread);

  // NEW: Prefix filter methods
  bool MatchesPrefix(hash160_t *h);
  Int  ClampKey(Int &key);
  void ParsePrefix(const std::string &hexPrefix);

  // NEW: Prefix filter data
  uint8_t  prefixBytes[20];
  int      prefixLength;
  int      prefixBitLen;
  bool     usePrefix;

  // NEW: Key range data
  Int      keyRangeStart;
  Int      keyRangeEnd;
  Int      keyRangeWidth;
  bool     useRange;

  // Original members
  Secp256K1 *secp;
  HashTable hashTable;
  uint64_t  counters[256];
  int       nbCPUThread;
  int       nbGPUThread;
  uint64_t  offsetCount;
  double    offsetTime;
  double    startTime;
  int       CPU_GRP_SIZE;
  bool      useGpu;
  bool      endOfSearch;
  bool      useSSE;
  bool      extraPoints;
  uint32_t  colSize;
  uint64_t  dMask;
  int       dpSize;
  int       initDPSize;
  int       nbFull;
  uint16_t  colMask;
  std::string outputFile;
  std::string workFile;
  uint32_t  saveWorkPeriod;
  std::string initialSeed;
  uint64_t  nbLoadedWalk;
  uint64_t  fetchedWalk;
  hash160_t *loadedX;
  hash160_t *loadedY;
  bool      saveRequest;

  // Precomputed key tables
  Int       seed;
  Int       *pub;
  Int       priv[10][65536];
  Point     Gp[10];
  Int       Kp[10];

  // Endomorphism constants
  Int       beta1;
  Int       lambda1;
  Int       beta2;
  Int       lambda2;

#ifdef WIN64
  HANDLE ghMutex;
#else
  pthread_mutex_t ghMutex;
#endif

};

#endif // BTCCOLLIDERH
