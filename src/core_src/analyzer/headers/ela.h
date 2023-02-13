#ifndef ELA_H_
#define ELA_H_
#include "LeakParams.h"
#include <iostream>
#include "SVF-FE/LLVMUtil.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "SVF-FE/SVFIRBuilder.h"
#include "Util/Options.h"
#include <time.h>
#include <map>
#include <set>
void printUseTime(string desc, clock_t start);
class ELA
{
private:
    SVFIR *pag;
    ICFG *icfg;
    SVFG *svfg;
    Andersen *ander;
    PTACallGraph *callgraph;
    Set<const SVFGNode *> sources;
    Set<const SVFGNode *> sinks;
    LeakParams leakParams;
    set<std::string> excludeFiles = {"enclave_t.c", "sgxsdk"};
    map<const SVFGNode *, bool> sourceMapping;
    map<const SVFGNode *, bool> sinkMapping;

public:
    ELA(std::vector<std::string> &mnv, string configFile)
    {
        if (configFile.compare("") != 0)
        {
            leakParams.readFromConfigFile(configFile);
        }
        std::cout << "EDL param entry num: " << leakParams.getLeakParams().size() << std::endl;
        SVFModule *svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(mnv);
        svfModule->buildSymbolTableInfo();
        SVFIRBuilder builder;
        pag = builder.build(svfModule);
        ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
        SVFGBuilder svfBuilder;
        // svfg = svfBuilder.buildPTROnlySVFG(ander);
        svfg = svfBuilder.buildFullSVFG(ander);
        icfg = pag->getICFG();
        // icfg->dump("icfg.dot");
        callgraph = ander->getPTACallGraph();
        // callgraph->dump("patCall.dot");
    }

    ~ELA()
    {
        delete svfg;
        AndersenWaveDiff::releaseAndersenWaveDiff();
        SVFIR::releaseSVFIR();
        SVF::LLVMModuleSet::releaseLLVMModuleSet();
        llvm::llvm_shutdown();
    }

    inline bool noNeedAnalysis(std::string filename)
    {
        for (auto exf : excludeFiles)
        {
            if (filename.find(exf) != filename.npos)
            {
                return true;
            }
        }
        return false;
    }
    inline ICFG *getICFG()
    {
        return icfg;
    }

    inline SVFG *getSVFG()
    {
        return svfg;
    }
    inline PAG *getPAG()
    {
        return pag;
    }
    inline PTACallGraph *getCG()
    {
        return callgraph;
    }
    inline void addToSources(const SVFGNode *svfgNode)
    {
        sourceMapping[svfgNode] = true;
        sources.insert(svfgNode);
    }
    inline void addToSinks(const SVFGNode *svfgNode)
    {
        sinkMapping[svfgNode] = true;
        sinks.insert(svfgNode);
    }
    void findSources();
    void findSinks();
    void ptrTaint(const SVF::SVFGNode *, const PAGNode *, int);
    void getNextLoadNodes(NodeID, NodeID, Set<NodeID> &);
    void traverseToFindCallNodeInsideFunction(NodeID start, string funcName, Set<NodeID> &ret);
    void printSinks();
    void getSinksSourceLocations(Set<string> &locs);
    void backwardTracking();
    void DFS(Set<const SVF::VFGNode *> &, std::vector<const SVF::VFGNode *> &, const SVF::SVFGNode *, bool, int);
    void DFS(Set<const SVF::VFGNode *> &, std::vector<const SVF::VFGNode *> &, const SVF::SVFGNode *,const SVF::SVFGNode *);
    void printPath(std::vector<const SVFGNode *> &path);
    void printICFGTraverseTime();
    void detectNullUseAnderson();
    void findMallocNotCheck();
    void DFS(Set<const PTACallGraphNode *> &visited, vector<const PTACallGraphNode *> &path, const PTACallGraphNode *src, const PTACallGraphNode *dst);
    void sourceTask(void *arg, int i);
    void sinkTask(void *arg, int i);
    void backwardTask(void *arg, int i,bool reverse, int depth);
};
#endif