/*
 * This file is part of the ECC project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The ECC developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "crypto/sha256.h"
#include "txdb.h"
#include "miner.h"
#include "kernel.h"
#include "crypto/scrypt.h"
#include "txmempool.h"
#include "util/util.h"
#include "args.h"
#include "init.h"
#include "consensus/consensus.h"
#include "txmempool.h"
#include "util/utilmoneystr.h"
#include "timedata.h"
#include "coins.h"
#include "networks/networktemplate.h"
#include "consensus/validation.h"
#include "consensus/merkle.h"
#include "processblock.h"
#include "networks/netman.h"
#include "net.h"
#include "policy/policy.h"

#include <thread>
#include <queue>

extern CWallet* pwalletMain;

typedef std::tuple<double, double, CTransaction*> TxPriority;

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
int64_t nLastCoinStakeSearchInterval = 0;
double dHashesPerSec;
int64_t nHPSTimerStart;


//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    std::set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        LogPrintf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString().substr(0,10).c_str(), dPriority, dFeePerKb);
        for (auto hash: setDependsOn)
            LogPrintf("   setDependsOn %s\n", hash.ToString().substr(0,10).c_str());
    }
};

// We want to sort transactions by priority and fee, so:
typedef std::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (std::get<1>(a) == std::get<1>(b))
                return std::get<0>(a) < std::get<0>(b);
            return std::get<1>(a) < std::get<1>(b);
        }
        else
        {
            if (std::get<0>(a) == std::get<0>(b))
                return std::get<1>(a) < std::get<1>(b);
            return std::get<0>(a) < std::get<0>(b);
        }
    }
};

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b)
    {
        return CompareTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};

// CreateNewBlock:
//   fProofOfStake: try (best effort) to make a proof-of-stake block
std::unique_ptr<CBlockTemplate> CreateNewBlock(CWallet* pwallet, bool fProofOfStake)
{
    CReserveKey reservekey(pwallet);

    // Create new block
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
    {
        return nullptr;
    }
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    CPubKey vchPubKey;
    reservekey.GetReservedKey(vchPubKey);
    txNew.vout[0].scriptPubKey << vchPubKey << OP_CHECKSIG;

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(MakeTransactionRef(txNew));
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = gArgs.GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = gArgs.GetArg("-blockprioritysize", 27000);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = gArgs.GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CTxMemPool::setEntries inBlock;
    CTxMemPool::setEntries waitSet;

    // ppcoin: if coinstake available add coinstake tx
    static int64_t nLastCoinStakeSearchTime = GetAdjustedTime();  // only initialized at startup
    CBlockIndex* pindexPrev = pnetMan->getChainActive()->chainActive.Tip();


    // This vector will be sorted into a priority queue:
    std::vector<TxCoinAgePriority> vecPriority;
    TxCoinAgePriorityCompare pricomparer;
    std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;
    std::priority_queue<CTxMemPool::txiter, std::vector<CTxMemPool::txiter>, ScoreCompare> clearedTxs;
    uint64_t nBlockSize = 1000;
    uint64_t nBlockTx = 0;
    unsigned int nBlockSigOps = 100;
    int lastFewTxs = 0;
    CAmount nFees = 0;


    if (fProofOfStake)  // attempt to find a coinstake
    {
        pblock->nBits = GetNextTargetRequired(pindexPrev, true);


        CTransaction txCoinStake;
        txCoinStake.nTime = GetTime();
        int64_t nSearchTime = txCoinStake.nTime; // search to current time


        if (nSearchTime > nLastCoinStakeSearchTime)
        {
            // LogPrintf(">>> OK1\n");
            if (pwallet->CreateCoinStake(*pwallet, pblock->nBits, nSearchTime-nLastCoinStakeSearchTime, txCoinStake))
            {
                if (txCoinStake.nTime >= std::max(pindexPrev->GetMedianTimePast()+1, pindexPrev->GetBlockTime() - nMaxClockDrift))
                {   // make sure coinstake would meet timestamp protocol
                    // as it would be the same as the block timestamp
                    (*pblock->vtx[0]).vout[0].SetEmpty();
                    (*pblock->vtx[0]).nTime = txCoinStake.nTime;
                    pblock->vtx.push_back(MakeTransactionRef(txCoinStake));
                }
            }
            nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
            nLastCoinStakeSearchTime = nSearchTime;
        }
    }
    else
    {
        pblock->nBits = GetNextTargetRequired(pindexPrev, false);
    }
    // Collect memory pool transactions into the block
    {
        LOCK2(cs_main, mempool.cs);
        pindexPrev = pnetMan->getChainActive()->chainActive.Tip();
        const int nHeight = pindexPrev->nHeight + 1;
        pblock->nTime = GetAdjustedTime();
        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

        pblock->nVersion = 4;

        int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                                ? nMedianTimePast
                                : pblock->GetBlockTime();

        bool fPriorityBlock = nBlockPrioritySize > 0;
        if (fPriorityBlock) {
            vecPriority.reserve(mempool.mapTx.size());
            for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
                 mi != mempool.mapTx.end(); ++mi)
            {
                double dPriority = mi->GetPriority(nHeight);
                CAmount dummy;
                mempool.ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
                vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
            }
            std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        }

        CTxMemPool::indexed_transaction_set::nth_index<3>::type::iterator mi = mempool.mapTx.get<3>().begin();
        CTxMemPool::txiter iter;
        while (mi != mempool.mapTx.get<3>().end() || !clearedTxs.empty())
        {
            bool priorityTx = false;
            if (fPriorityBlock && !vecPriority.empty()) { // add a tx from priority queue to fill the blockprioritysize
                priorityTx = true;
                iter = vecPriority.front().second;
                actualPriority = vecPriority.front().first;
                std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                vecPriority.pop_back();
            }
            else if (clearedTxs.empty()) { // add tx with next highest score
                iter = mempool.mapTx.project<0>(mi);
                mi++;
            }
            else {  // try to add a previously postponed child tx
                iter = clearedTxs.top();
                clearedTxs.pop();
            }

            if (inBlock.count(iter))
                continue; // could have been added to the priorityBlock

            const CTransaction& tx = iter->GetTx();

            bool fOrphan = false;
            for (auto parent: mempool.GetMemPoolParents(iter))
            {
                if (!inBlock.count(parent)) {
                    fOrphan = true;
                    break;
                }
            }
            if (fOrphan) {
                if (priorityTx)
                    waitPriMap.insert(std::make_pair(iter,actualPriority));
                else
                    waitSet.insert(iter);
                continue;
            }

            unsigned int nTxSize = iter->GetTxSize();
            if (fPriorityBlock &&
                (nBlockSize + nTxSize >= nBlockPrioritySize || !AllowFree(actualPriority))) {
                fPriorityBlock = false;
                waitPriMap.clear();
            }
            if (!priorityTx &&
                (iter->GetModifiedFee() < ::minRelayTxFee.GetFee(nTxSize) && nBlockSize >= nBlockMinSize)) {
                break;
            }
            if (nBlockSize + nTxSize >= nBlockMaxSize) {
                if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) {
                    break;
                }
                // Once we're within 1000 bytes of a full block, only look at 50 more txs
                // to try to fill the remaining space.
                if (nBlockSize > nBlockMaxSize - 1000) {
                    lastFewTxs++;
                }
                continue;
            }

            if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
                continue;

            unsigned int nTxSigOps = iter->GetSigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS) {
                if (nBlockSigOps > MAX_BLOCK_SIGOPS - 2) {
                    break;
                }
                continue;
            }

            CAmount nTxFees = iter->GetFee();
            // Added
            pblock->vtx.push_back(MakeTransactionRef(tx));
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            inBlock.insert(iter);

            // Add transactions that depend on this one to the priority queue
            for (auto child: mempool.GetMemPoolChildren(iter))
            {
                if (fPriorityBlock) {
                    waitPriIter wpiter = waitPriMap.find(child);
                    if (wpiter != waitPriMap.end()) {
                        vecPriority.push_back(TxCoinAgePriority(wpiter->second,child));
                        std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                        waitPriMap.erase(wpiter);
                    }
                }
                else {
                    if (waitSet.count(child)) {
                        clearedTxs.push(child);
                        waitSet.erase(child);
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        if (pblock->IsProofOfStake())
        {
            pblock->nTime      = pblock->vtx[1]->nTime; //same as coinstake timestamp
            pblock->nTime      = std::max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime      = std::max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);

        }
        else
        {
            pblock->nTime          = std::max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime          = std::max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
        }
        if (pblock->IsProofOfWork())
        {
            pblock->UpdateTime();
            pblock->vtx[0]->vout[0].nValue = GetProofOfWorkReward(nFees, pindexPrev->nHeight+1, pindexPrev->GetBlockHash());

        }
        pblock->nNonce         = 0;
    }

    return std::move(pblocktemplate);
}


void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    pblock->vtx[0]->vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0]->vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

bool CheckWork(const std::shared_ptr<const CBlock> pblock, CWallet& wallet, CReserveKey& reservekey)
{
    arith_uint256 hash = UintToArith256(pblock->GetHash());
    arith_uint256 hashTarget = arith_uint256(pblock->nBits);

    if (hash > hashTarget && pblock->IsProofOfWork())
        return error("Miner : proof-of-work not meeting target");

    //// debug print
    LogPrintf("Miner:\n");
    LogPrintf("new block found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0]->vout[0].nValue).c_str());

    // Found a solution
    {
        {
            LOCK(cs_main);
            if (pblock->hashPrevBlock != pnetMan->getChainActive()->chainActive.Tip()->GetBlockHash())
                return error("BMiner : generated block is stale");
        }

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[pblock->GetHash()] = 0;
        }

        // Process this block the same as if we had received it from another node
        CValidationState state;
        const CNetworkTemplate& chainparams = pnetMan->getActivePaymentNetwork();
        if (!ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL))
            return error("Miner : ProcessBlock, block not accepted");
    }

    return true;
}

void EccMiner(CWallet *pwallet)
{
    void *scratchbuf = scrypt_buffer_alloc();
    LogPrintf("CPUMiner started for proof-of-%s\n", "stake");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    // Make this thread recognisable as the mining thread
    RenameThread("ecc-miner");
    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;
    while (true)
    {
        if (fShutdown)
            return;
        if(!g_connman)
        {
            MilliSleep(1000);
            if (fShutdown)
                return;
        }
        while (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) < 6 || pnetMan->getChainActive()->IsInitialBlockDownload() || pwallet->IsLocked())
        {
            MilliSleep(1000);
            if (fShutdown)
                return;
        }
        //
        // Create new block
        //
        unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrev = pnetMan->getChainActive()->chainActive.Tip();
        std::unique_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(pwallet, true));
        if (!pblocktemplate.get())
        {
            LogPrintf("Error in Miner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
            return;
        }
        CBlock *pblock = &pblocktemplate->block;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);
        LogPrintf("Running Miner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
               ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));
        //
        // Search
        //
        int64_t nStart = GetTime();
        arith_uint256 hashTarget = arith_uint256(pblock->nBits);
        unsigned int max_nonce = 0xffff0000;
        CBlockHeader res_header;
        arith_uint256 result;
        while(true)
        {
            unsigned int nHashesDone = 0;
            unsigned int nNonceFound;

            nNonceFound = scanhash_scrypt(
                        (CBlockHeader *)&pblock->nVersion,
                        scratchbuf,
                        max_nonce,
                        nHashesDone,
                        UBEGIN(result),
                        &res_header
            );

            // Check if something found
            if (nNonceFound != (unsigned int) -1)
            {
                if (result <= hashTarget)
                {
                    // Found a solution
                    pblock->nNonce = nNonceFound;
                    assert(result == UintToArith256(pblock->GetHash()));
                    if (!pblock->SignScryptBlock(*pwalletMain))
                    {
                        break;
                    }
                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    const std::shared_ptr<const CBlock> spblock = std::make_shared<const CBlock>(*pblock);
                    CheckWork(spblock, *pwalletMain, reservekey);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);
                    break;
                }
            }
            // Meter hashes/sec
            static int64_t nHashCounter;
            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter = 0;
            }
            else
                nHashCounter += nHashesDone;
            if (GetTimeMillis() - nHPSTimerStart > 4000)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (GetTimeMillis() - nHPSTimerStart > 4000)
                    {
                        dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = GetTimeMillis();
                        nHashCounter = 0;
                    }
                }
            }
            // Check for stop or if block needs to be rebuilt
            if (fShutdown)
                return;
            if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL))
                break;
            if (nNonceFound >= 0xffff0000)
                break;
            if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != pnetMan->getChainActive()->chainActive.Tip())
                break;
            // Update nTime every few seconds
            pblock->nTime = std::max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime = std::max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
            pblock->UpdateTime();
            if (pblock->GetBlockTime() >= (int64_t)pblock->vtx[0]->nTime + nMaxClockDrift)
                break;  // need to update coinbase timestamp
        }
    }
    scrypt_buffer_free(scratchbuf);
}

void EccMinter(CWallet *pwallet)
{
    LogPrintf("CPUMiner started for proof-of-%s\n", "stake");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    // Make this thread recognisable as the mining thread
    RenameThread("ecc-minter");
    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;
    while (true)
    {
        if (fShutdown)
            return;
        if(!g_connman)
        {
            MilliSleep(1000);
            if (fShutdown)
                return;
        }
        while (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) < 6 || pnetMan->getChainActive()->IsInitialBlockDownload() || pwallet->IsLocked())
        {
            MilliSleep(1000);
            if (fShutdown)
                return;
        }
        //
        // Create new block
        //
        CBlockIndex* pindexPrev = pnetMan->getChainActive()->chainActive.Tip();
        std::unique_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(pwallet, true));
        if (!pblocktemplate.get())
        {
            LogPrintf("Error in Miner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
            return;
        }
        CBlock *pblock = &pblocktemplate->block;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);
        // ppcoin: if proof-of-stake block found then process block
        if (pblock->IsProofOfStake())
        {
            if (!pblock->SignScryptBlock(*pwalletMain))
            {
                continue;
            }
            LogPrintf("CPUMiner : proof-of-stake block found %s\n", pblock->GetHash().ToString().c_str());
            SetThreadPriority(THREAD_PRIORITY_NORMAL);
            const std::shared_ptr<const CBlock> spblock = std::make_shared<const CBlock>(*pblock);
            CheckWork(spblock, *pwalletMain, reservekey);
            SetThreadPriority(THREAD_PRIORITY_LOWEST);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1)); // 1 second delay
        continue;
    }
}




std::vector<std::thread> minerThreads;

void ThreadMiner(void* parg, bool shutdownOnly)
{

    if (minerThreads.size() != 0)
    {
        std::vector<std::thread>::iterator iter;
        for(iter = minerThreads.begin(); iter != minerThreads.end(); iter++)
        {
            (*iter).join();
        }
        LogPrintf("CPUMiner stopped for proof-of-%s\n", "stake");
        return;
    }
    if(shutdownOnly)
    {
        LogPrintf("CPUMiner stopped for proof-of-%s\n", "stake");
        return;
    }

    CWallet* pwallet = (CWallet*)parg;
    try
    {
        minerThreads.push_back(std::thread((boost::bind(&EccMinter, pwallet))));
    }
    catch (std::exception& e)
    {
        PrintException(&e, "ThreadECCMinter()");
    }
    catch (...)
    {
        PrintException(NULL, "ThreadECCMinter()");
    }
    nHPSTimerStart = 0;
    dHashesPerSec = 0;
    LogPrintf("ThreadECCMinter exiting \n");
}
