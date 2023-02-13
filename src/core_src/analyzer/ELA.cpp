#include "headers/LeakParams.h"
#include <iostream>
#include "SVF-FE/LLVMUtil.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "SVF-FE/SVFIRBuilder.h"
#include "Util/Options.h"
#include <time.h>
#include "headers/ela.h"
#include "headers/test.h"
#include "headers/difflib.h"
#include <iostream>
#include <set>
#include <thread>
#include <string>
#include <vector>
#include <climits>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
auto console = spdlog::stdout_color_mt("console");

void print(std::stringstream &ss)
{
	spdlog::get("console")->info(ss.str());
}

#define DEBUG 0
#define REGRESSION 0

std::mutex coutMutex;

// using namespace llvm;
using namespace std;
// using namespace SVF;
// using namespace SVFUtil;
using namespace difflib;

const int THREAD_NUM = 20;
Set<const SVFGNode *> sourceArr[THREAD_NUM];
Set<const SVFGNode *> sinkArr[THREAD_NUM];

struct timer
{
	timer(std::string t) : title(t) { start = std::chrono::system_clock::now(); }
	~timer()
	{
		auto end = std::chrono::system_clock::now();
		mills = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
		std::stringstream ss;
		ss << title << " use time: " << mills << std::endl;
		print(ss);
	}
	std::chrono::system_clock::time_point start;
	int64_t mills;
	std::string title;
};

ELA *ela;

void sourceTaskWrapper(void *arg, int i)
{
	ela->sourceTask(arg, i);
}

void ELA::sourceTask(void *arg, int i)
{
	std::string keywords[] = {
		"user",
		"password",
		"passwd",
		"pwd",
		"birthday",
		"mail",
		"relationship",
		"phone",
		"gps",
		"zip",
		"secret",
		"credential",
		"private",
		"encrypt",
		"decrypt",
		"key",
		"aes",
		"des"};

	// auto &data = *(std::vector<SVF::GenericVFGTy::iterator> *)arg;
	auto &data = *(std::vector<SVF::VFGNode *> *)arg;
	for (auto it : data)
	{
		SVFGNode *svfgNode = it;

		if (noNeedAnalysis(svfgNode->toString()))
		{
			continue;
		}

		if (FormalParmVFGNode::classof(svfgNode) || AddrVFGNode::classof(svfgNode))
		{
			std::string cmdStr = svfgNode->toString();
			Set<std::string> wordsInVariableName;
			std::string variableName = "";
			bool flag = false;
			std::string word = "";
			for (int i = 0; i < cmdStr.length(); i++)
			{
				if (cmdStr[i] == '%')
				{
					flag = true;
					continue;
				}
				if (flag && (cmdStr[i] == ' ' || cmdStr[i] == '_'))
				{
					wordsInVariableName.insert(word);
					if (cmdStr[i] == ' ')
					{
						flag = false;
						break;
					}
				}
				if (flag && cmdStr[i] != '_')
				{
					word += tolower(cmdStr[i]);
				}

				if (flag && cmdStr[i] == '_')
				{
					word = "";
				}
				if (flag)
				{
					variableName += cmdStr[i];
				}
			}
			bool isSensitive = false;
			for (auto word : wordsInVariableName)
			{
				for (auto keyword : keywords)
				{
					if (difflib::MakeSequenceMatcher<>(keyword, word).ratio() > 0.8)
					{
						std::stringstream ss;
						ss << "find sensitive variable: " << word << " in " << variableName << " (hit keyword " << keyword << ")"
						   << "\n";
						isSensitive = true;
						break;
					}
				}
				if (isSensitive)
				{
					break;
				}
			}
			if (isSensitive)
			{
				if (svfgNode->toString().find("retval") == svfgNode->toString().npos &&
					svfgNode->toString().find("filename") == svfgNode->toString().npos)
				{
					// addToSources(svfgNode);
					sourceArr[i].insert(svfgNode);
				}
			}
		}
	}
}

void sinkTaskWrapper(void *arg, int i)
{
	ela->sinkTask(arg, i);
}

void ELA::sinkTask(void *arg, int i)
{
	auto &data = *(std::vector<SVF::GenericCallGraphTy::iterator> *)arg;

	for (auto it : data)
	{
		PTACallGraphNode *ptaCallGraphNode = it->second;
		auto func = ptaCallGraphNode->getFunction();
		int paramSize = leakParams.getLeakParams().size();
		for (auto param : leakParams.getLeakParams())
		{
			if (func->getName() == "sgx_rsa_pub_encrypt_sha256" || func->getName() == "sgx_rsa_priv_decrypt_sha256" || func->getName() == "sgx_seal_data" || func->getName() == "sgx_rijndael128GCM_decrypt")
			{
				PTACallGraphEdge::CallInstSet csSet;
				callgraph->getAllCallSitesInvokingCallee(ptaCallGraphNode->getFunction(), csSet);
				for (auto callICFGNode : csSet)
				{
					int paramIdx = 3;

					if (func->getName() == "sgx_rsa_priv_decrypt_sha256")
					{
						paramIdx = 1;
					}

					auto paramVec = callICFGNode->getActualParms();
					if (paramIdx < paramVec.size())
					{
						auto var = paramVec[paramIdx];
						if (var && var->hasValue())
						{
							auto pagNodeId = pag->getValueNode(var->getValue());
							auto pagNode = pag->getGNode(pagNodeId);
							const SVFGNode *source = svfg->getDefSVFGNode(pagNode);
							if (LoadSVFGNode::classof(source))
							{
								LoadSVFGNode *loadSVFGNode = (LoadSVFGNode *)source;
								auto src = svfg->getDefSVFGNode(loadSVFGNode->getPAGSrcNode());
								stringstream ss;
								ss << "特殊函数的source点:"
								   << "\n";
								ss << src->toString() << "\n";
								print(ss);
								// addToSources(src);
								sourceArr[i].insert(src);
							}
							else
							{
								stringstream ss;
								ss << "特殊函数的source点:"
								   << "\n";
								ss << source->toString() << "\n";
								print(ss);
								// addToSources(source);
								sourceArr[i].insert(source);
							}
						}
						else
						{
							stringstream ss;
							ss << "funcname: " << param.getFuncName() << ", param index: " << param.getParamIndex() << "no value!"
							   << "\n";
							print(ss);
						}
					}
					else
					{
						stringstream ss;
						ss << "funcname: " << param.getFuncName() << ", param index: " << param.getParamIndex() << "\n";
						ss << "index " << paramIdx << "out of range!, size " << paramVec.size() << "\n";
						print(ss);
					}
				}
			}

			if (func->getName() == param.getFuncName())
			{
				if (param.getLeakType() == "ECALL_OUT" ||
					param.getLeakType() == "ECALL_USER_CHECK" ||
					param.getLeakType() == "ECALL_ADT")
				{

					auto funEntryICFGNode = icfg->getFunEntryICFGNode(func);
					string funEntryICFGNodeStr = funEntryICFGNode->toString();
					if (noNeedAnalysis(funEntryICFGNodeStr))
					{
						break;
					}

					auto var = funEntryICFGNode->getFormalParms()[param.getParamIndex()];
					if (var)
					{
						NodeID pagNodeId = pag->getValueNode(var->getValue());
						PAGNode *pagNode = pag->getGNode(pagNodeId);
						auto svfgNode = svfg->getDefSVFGNode(pagNode);
						ptrTaint(svfgNode, pagNode, i);
					}
				}
				// write to a pointer returned from an OCALL is a leak risk
				else if (param.getLeakType() == "OCALL_RETURN")
				{
					// find all callers
					PTACallGraphEdge::CallInstSet csSet;
					callgraph->getAllCallSitesInvokingCallee(ptaCallGraphNode->getFunction(), csSet);
					for (auto callICFGNode : csSet)
					{
						auto var = callICFGNode->getActualParms()[param.getParamIndex()];
						Set<NodeID> taints;
						auto pagNodeId = pag->getValueNode(var->getValue());
						// e.g. %p = load(int* , %ActualParm),we mark %p as tainted.
						// because the attacker may modify the content(is a pointer) in %ActualParm
						// %p may point to untrusted memory.
						getNextLoadNodes(callICFGNode->getId(), pagNodeId, taints);
						if (taints.size() > 0)
						{
							for (auto id : taints)
							{
								auto ptr = pag->getGNode(id);
								auto svfgNode = svfg->getDefSVFGNode(pag->getGNode(id));
								ptrTaint(svfgNode, ptr, i);
							}
						}
					}
				}
				else if (param.getLeakType() == "OCALL_IN" ||
						 param.getLeakType() == "OCALL_IN_NON_PTR")
				{
					PTACallGraphEdge::CallInstSet csSet;
					callgraph->getAllCallSitesInvokingCallee(ptaCallGraphNode->getFunction(), csSet);
					for (auto callICFGNode : csSet)
					{

						int paramIdx = param.getParamIndex();
						auto paramVec = callICFGNode->getActualParms();
						if (paramIdx < paramVec.size())
						{
							auto var = paramVec[paramIdx];
							if (var && var->hasValue())
							{
								auto pagNodeId = pag->getValueNode(var->getValue());
								auto pagNode = pag->getGNode(pagNodeId);
								SVFGNode *snk = getSVFG()->getActualParmVFGNode(pagNode, callICFGNode);
								addToSinks(snk);
							}
							else
							{
								std::stringstream ss;
								ss << "funcname: " << param.getFuncName() << ", param index: " << param.getParamIndex() << "no value!"
								   << "\n";
								print(ss);
							}
						}
						else
						{
							std::stringstream ss;
							ss << "funcname: " << param.getFuncName() << ", param index: " << param.getParamIndex() << "\n";
							ss << "index " << paramIdx << "out of range!, size " << paramVec.size() << "\n";
							print(ss);
						}
					}
				}
			}
		}

		// find malloc without check
		// auto callee = ptaCallGraphNode->getFunction();
		// if (callee)
		// {
		//     string calleeFuncName = callee->getName();
		//     if (calleeFuncName.find("alloc") != string::npos)
		//     {
		//         PTACallGraphEdge::CallInstSet csSet;
		//         callgraph->getAllCallSitesInvokingCallee(callee, csSet);
		//         for (auto cs : csSet)
		//         {
		//             auto tmp = cs->toString();
		//             if (tmp.find("nclave_t.c") != tmp.npos)
		//             {
		//                 continue;
		//             }
		//             auto stmts = cs->getSVFStmts();
		//             for (auto stmt : stmts)
		//             {
		//                 if (AddrStmt::classof(stmt))
		//                 {
		//                     bool checked = false;
		//                     bool stored = false;
		//                     auto obj = stmt->getSrcNode()->getId();
		//                     if (!checked)
		//                     {
		//                         auto aliasPointers = ander->getRevPts(obj);
		//                         for (auto pointer : aliasPointers)
		//                         {
		//                             if (!pag->hasGNode(pointer) || !pag->isValidPointer(pointer))
		//                             {
		//                                 continue;
		//                             }
		//                             if (pag->getGNode(pointer)->getInEdges().empty())
		//                             {
		//                                 continue;
		//                             }
		//                             auto aliasDefNode = svfg->getDefSVFGNode(pag->getGNode(pointer));
		//                             for (auto edge : aliasDefNode->getOutEdges())
		//                             {
		//                                 if (CmpVFGNode::classof(edge->getDstNode()))
		//                                 {
		//                                     checked = true;
		//                                 }
		//                             }
		//                         }
		//                         if (!checked)
		//                         {
		//                             for (auto pointer : aliasPointers)
		//                             {
		//                                 if (!pag->hasGNode(pointer) || !pag->isValidPointer(pointer))
		//                                 {
		//                                     continue;
		//                                 }
		//                                 if (pag->getGNode(pointer)->getInEdges().empty())
		//                                 {
		//                                     continue;
		//                                 }
		//                                 auto aliasDefNode = svfg->getDefSVFGNode(pag->getGNode(pointer));

		//                                 for (auto edge : aliasDefNode->getOutEdges())
		//                                 {
		//                                     if (StoreVFGNode::classof(edge->getDstNode()))
		//                                     {
		//                                     }
		//                                 }
		//                             }
		//                         }
		//                     }
		//                 }
		//             }
		//         }
		//     }
		// }
	}
	std::stringstream ss;
	ss << "thread" << i << "Finished!" << endl;
	print(ss);
}

int getBudget(const SVFGNode *src, const SVFGNode *dst)
{

	int budget = 0;
	FIFOWorkList<const SVFGNode *> worklist;
	Set<const SVFGNode *> visited;
	worklist.push(src);
	/// Traverse along VFG
	while (!worklist.empty())
	{
		vector<const SVFGNode *> levelNodes;
		while (!worklist.empty())
		{
			levelNodes.push_back(worklist.pop());
		}

		for (auto node : levelNodes)
		{
			if (node == dst)
			{
				return budget;
			}

			for (SVFGNode::const_iterator it = node->InEdgeBegin(), eit =
																		node->InEdgeEnd();
				 it != eit; ++it)
			{
				SVFGEdge *edge = *it;
				SVFGNode *succNode = edge->getSrcNode();
				if (visited.find(succNode) == visited.end())
				{
					visited.insert(succNode);
					worklist.push(succNode);
				}
			}
		}
		budget++;
	}
	return -1;
}

void backwardTaskWrapper(void *arg, int i, bool reverse, int depth)
{
	ela->backwardTask(arg, i, reverse, depth);
}

void ELA::backwardTask(void *arg, int i, bool reverse, int depth)
{

	auto &data = *(std::vector<const SVFGNode *> *)arg;
	for (auto item : data)
	{
		// std::cout << std::this_thread::get_id() << ": " << proced << "/" << data.size() << std::"\n";
		// if (reverse)
		// {
		//     if (StoreSVFGNode::classof(item))
		//     {
		//         StoreSVFGNode *s = (StoreSVFGNode *)item;
		//         const VFGNode *src = svfg->getDefSVFGNode(s->getPAGSrcNode());
		//         item = src;
		//     }
		// }

		// std::vector<const SVFGNode *> path;
		// std::set<const SVFGNode *> visited;
		// //DFS(visited, path, item, reverse, depth);
		// proced++;

		std::vector<const SVFGNode *> path;
		Set<const SVFGNode *> visited;
		for (auto source : sources)
		{
			if (-1 != getBudget(item, source))
			{
				DFS(visited, path, item, source);
			}
		}
	}
}

void ELA::DFS(Set<const PTACallGraphNode *> &visited, vector<const PTACallGraphNode *> &path, const PTACallGraphNode *src, const PTACallGraphNode *dst)
{
	if (src->getId() == dst->getId())
	{
		path.push_back(src);
		for (auto i : path)
		{
			std::cout << i->getFunction()->getName() << "====>";
		}
		std::cout << "\n";
		path.pop_back();
		return;
	}

	if (src->getOutEdges().size() == 0)
	{
		std::cout << "已到尽头!"
				  << "\n";
		return;
	}

	visited.insert(src);
	path.push_back(src);
	for (auto edge : src->getOutEdges())
	{
		// for loop
		if (visited.find(edge->getDstNode()) == visited.end())
		{
			DFS(visited, path, edge->getDstNode(), dst);
		}
	}
	visited.erase(src);
	path.pop_back();
}

void ELA::detectNullUseAnderson()
{
	for (auto it = icfg->begin(), iEnd = icfg->end(); it != iEnd; it++)
	{
		auto node = it->second;
		if (CallICFGNode::classof(node))
		{
			CallICFGNode *callICFGNode = (CallICFGNode *)node;
			CallInst *ci = (CallInst *)(callICFGNode->getCallSite());
			Function *callee = ci->getCalledFunction();
			string calleeFuncName = "";
			if (!callee)
			{
				for (auto indirectCall : callgraph->getIndCallMap())
				{
					for (auto svfcallee : indirectCall.second)
					{
						calleeFuncName = svfcallee->getLLVMFun()->getName().str();
#if DEBUG
                        std::cout << "indirect call:" << calleeFuncName << std::endl;
#endif
                    }
                }
            }
            else
            {
                calleeFuncName = callee->getName().str();
#if DEBUG
                std::cout << "direct call:" << calleeFuncName << std::endl;
#endif
            }

            // if (calleeFuncName.compare("memcpy") == 0)
            // {
            // cout << calleeFuncName << endl;
            // }
            if (calleeFuncName.find("memcpy") != string::npos)
            {
                auto dst = callICFGNode->getActualParms()[0];
                auto dstPagId = pag->getValueNode(dst->getValue());
                if (ander->getPts(dstPagId).empty())
                {
                    cout << callICFGNode->toString() << endl;
                }
            }
        }

        // if(IntraICFGNode::classof(node)){
        //     IntraICFGNode* intraICFGNode = (IntraICFGNode*)node;
        //     auto stmts = intraICFGNode->getSVFStmts();
        //     for(auto stmt : stmts){
        //         cout << stmt->toString() << endl;
        //         if(StoreStmt::classof(stmt)){
        //             StoreStmt* storeStmt = (StoreStmt*)stmt;
        //             auto storeDstId = storeStmt->getLHSVarID();
        //             if (ander->getPts(storeDstId).empty()){
        //                 cout << storeStmt->toString() << endl;
        //             }

		//         }
		//     }
		// }
	}
}

// void ELA::getSinksSourceLocations(set<string> &locs)
// {

//     // getSourceLoc(getInst())
//     for (auto sink : sinks)
//     {
//         ICFGNode *node = icfg->getGNode(sink);
//         if (CallICFGNode::classof(node))
//         {
//             CallICFGNode *callICFGNode = (CallICFGNode *)node;
//             std::string loc = getSourceLoc(callICFGNode->getCallSite());
//             assert(loc != "");
//             locs.insert(loc);
//         }
//         else if (IntraICFGNode::classof(node))
//         {
//             IntraICFGNode *intraICFGNode = (IntraICFGNode *)node;
//             intraICFGNode->toString();
//             std::string loc = getSourceLoc(intraICFGNode->getInst());
//             assert(loc != "");
//             locs.insert(loc);
//         }
//         else
//         {
//             assert(0 == 1);
//         }
//     }
// }
void ELA::findMallocNotCheck()
{
	clock_t start = clock();
	auto totalCGNum = callgraph->getTotalNodeNum();
	for (auto it = callgraph->begin(), iEnd = callgraph->end(); it != iEnd; it++)
	{
		// std::cout << "CGNum: " << totalCGNum-- << std::endl;
		auto node = it->second;

		auto callee = node->getFunction();
		if (callee)
		{
			string calleeFuncName = callee->getName();
			if (calleeFuncName.find("alloc") != string::npos)
			{
				PTACallGraphEdge::CallInstSet csSet;
				callgraph->getAllCallSitesInvokingCallee(callee, csSet);
				for (auto cs : csSet)
				{
					auto tmp = cs->toString();
					if (tmp.find("nclave_t.c") != tmp.npos)
					{
						continue;
					}
					auto stmts = cs->getSVFStmts();
					for (auto stmt : stmts)
					{
						if (AddrStmt::classof(stmt))
						{
							bool checked = false;
							bool stored = false;
							auto obj = stmt->getSrcNode()->getId();
							if (!checked)
							{
								auto aliasPointers = ander->getRevPts(obj);
								for (auto pointer : aliasPointers)
								{
									// if (!pag->hasGNode(pointer) || !pag->isValidPointer(pointer))
									// {
									// 	continue;
									// }
									// if (pag->getGNode(pointer)->getInEdges().empty())
									// {
									// 	continue;
									// }
									// auto aliasDefNode = svfg->getDefSVFGNode(pag->getGNode(pointer));
									// for (auto edge : aliasDefNode->getOutEdges())
									// {
									// 	if (CmpVFGNode::classof(edge->getDstNode()))
									// 	{
									// 		checked = true;
									// 	}
									// }

									auto inEdges = pag->getGNode(pointer)->getInEdges();
									auto outEdges = pag->getGNode(pointer)->getOutEdges();
									for (auto edge : outEdges)
									{
										if (CmpStmt::classof(edge))
										{
											checked = true;
											break;
										}
									}

									for (auto edge : inEdges)
									{
										if (StoreStmt::classof(edge))
										{
											auto s = edge->toString();
											// only focus on large memory copy
											// if (s.find("memcpy") != s.npos || s.find("strcpy") != s.npos)
											// {
											if (!checked)
											{

												if (cs->getFun()->getName() == edge->getICFGNode()->getFun()->getName())
												{
													std::cout << "**********************NULL BUFFER COPY(intra)******************" << std::endl;
												}
												else
												{
													std::cout << "**********************NULL BUFFER COPY(inter)******************" << std::endl;
												}
												std::cout << "alloc site:" << endl;
												std::cout << cs->toString() << endl;
												std::cout << std::endl
														  << std::endl;
												std::cout << "buffer copy:" << endl;
												std::cout << edge->toString() << endl;
												std::cout << "*********************************************************" << std::endl;
												std::cout << std::endl
														  << std::endl;

												// const RetICFGNode *retBlockNode = cs->getRetICFGNode();
												// const PAGNode *pagNode = pag->getCallSiteRet(retBlockNode);
												// const SVFGNode *node = getSVFG()->getDefSVFGNode(pagNode);
												// std::cout << "内存分配点：" << endl;
												// std::cout << node->toString() << endl;
												// // addToTaintPointers(pagNode);
												// // ptrTaint(node);
												// auto a = svfg->getDefSVFGNode(edge->getSrcNode());
												// cout << "aaa: " << a << endl;
												// addToSinks();
											}
											// }
										}
									}
									// }
									// if (!checked)
									// {
									// 	for (auto pointer : aliasPointers)
									// 	{
									// 		if (!pag->hasGNode(pointer) || !pag->isValidPointer(pointer))
									// 		{
									// 			continue;
									// 		}
									// 		if (pag->getGNode(pointer)->getInEdges().empty())
									// 		{
									// 			continue;
									// 		}
									// 		auto aliasDefNode = svfg->getDefSVFGNode(pag->getGNode(pointer));

									// 		for (auto edge : aliasDefNode->getOutEdges())
									// 		{
									// 			auto s = edge->getDstNode()->toString();
									// 			if (StoreVFGNode::classof(edge->getDstNode()))
									// 			{
									// 				if (s.find("memcpy") != s.npos || s.find("strcpy") != s.npos){
									// 					cout << "malloc site" << stmt->toString() << endl;
									// 					cout << "NULL copy: " << edge->getDstNode()->toString() << endl;
									// 				}

									// 			}
									// 		}
									// 	}
									// }
								}
							}
						}
					}
				}
			}
		}
	}
}

void ELA::printSinks()
{
	std::cout << "\n======================sinks==========================" << std::endl;
	for (auto sink : sinks)
	{
		std::cout << sink->toString() << std::endl;
	}
	std::cout << "=====================================================" << std::endl;
}

template <class T>
bool inSet(const T *node, Set<const T *> &s)
{
	if (s.find(node) != s.end())
	{
		return true;
	}
	else
	{
		return false;
	}
}

void ELA::ptrTaint(const SVF::VFGNode *vNode, const PAGNode *ptr, int idx)
{
#if DEBUG
	std::cout << "def node:" << std::endl;
	std::cout << vNode->toString() << std::endl;
	std::cout << "taint propagating..." << std::endl;
#endif

	FIFOWorkList<const VFGNode *> worklist;
	Set<const VFGNode *> visited = {vNode};
	std::vector<const VFGNode *> tmp = {vNode};
	worklist.push(vNode);

	while (!worklist.empty())
	{
		const VFGNode *vNode = worklist.pop();
		for (VFGNode::const_iterator it = vNode->OutEdgeBegin(), eit =
																	 vNode->OutEdgeEnd();
			 it != eit; ++it)
		{
			VFGEdge *edge = *it;
			VFGNode *succNode = edge->getDstNode();
			if (visited.find(succNode) == visited.end())
			{
				stringstream ss;
				ss << "push...\n";
				ss << succNode->toString();
				print(ss);

				visited.insert(succNode);
				tmp.push_back(succNode);
				worklist.push(succNode);
			}
		}
	}

	Set<const PAGNode *> taintPointers = {ptr};
	for (auto vNode : tmp)
	{
		if (noNeedAnalysis(vNode->toString()))
		{
			continue;
		}

		for (VFGNode::const_iterator it = vNode->OutEdgeBegin(), eit =
																	 vNode->OutEdgeEnd();
			 it != eit; ++it)
		{

			VFGEdge *edge = *it;
			VFGNode *succNode = edge->getDstNode();
			//[外带的指针，传播规则]
			// load statement
			// q = *p 如果指针p是tainted，那么读出来的值也标记为tainted
			if (LoadVFGNode::classof(succNode))
			{
				LoadVFGNode *loadVFGNode = (LoadVFGNode *)succNode;
				const PAGNode *srcPAGNode = loadVFGNode->getPAGSrcNode();
				if (inSet(srcPAGNode, taintPointers))
				{
#if DEBUG
					cout << "add pag node: " << loadVFGNode->getPAGDstNode()->toString() << endl;
#endif
					taintPointers.insert(loadVFGNode->getPAGDstNode());
				}
			}
			//[外带的指针，传播规则]
			// copy statement，bitcast命令
			// q = p,如果指针p是tainted，q也标记为tainted
			else if (CopyVFGNode::classof(succNode))
			{
				CopyVFGNode *copyVFGNode = (CopyVFGNode *)succNode;
				const PAGNode *srcPAGNode = copyVFGNode->getPAGSrcNode();
				if (inSet(srcPAGNode, taintPointers))
				{
#if DEBUG
					cout << "add pag node: " << copyVFGNode->toString() << endl;
#endif
					taintPointers.insert(copyVFGNode->getPAGDstNode());
				}
			}
			//[外带的指针，传播规则]
			//*q = p,如果p是tainted，p存入q所指向的内存，q也应该被标记为tainted
			//       如果p是untainted，p存入q所指向的内存，指针q应该被洗白，q去除污点标记，同时，这里是一处sink点
			else if (StoreVFGNode::classof(succNode))
			{
				StoreVFGNode *storeVFGNode = (StoreVFGNode *)succNode;
				const PAGNode *dstPAGNode = storeVFGNode->getPAGDstNode();
				const PAGNode *srcPAGNode = storeVFGNode->getPAGSrcNode();
				if (inSet(dstPAGNode, taintPointers) && !inSet(srcPAGNode, taintPointers))
				{
					std::stringstream ss;
					ss << "找到一处sink: " << storeVFGNode->toString() << endl;
					print(ss);
					addToSinks(storeVFGNode);
				}

				if (inSet(srcPAGNode, taintPointers) && !inSet(dstPAGNode, taintPointers))
				{
					taintPointers.insert(dstPAGNode);
				}
			}
			//[外带的指针，传播规则]
			// q = p.f,如果p是tainted，p.f也是tainted，读取p的域到q，q应该被标记为tainted
			else if (GepSVFGNode::classof(succNode))
			{
				GepSVFGNode *gepSVFGNode = (GepSVFGNode *)succNode;
				const PAGNode *srcPAGNode = gepSVFGNode->getPAGSrcNode();
				if (inSet(srcPAGNode, taintPointers))
				{
					taintPointers.insert(gepSVFGNode->getPAGDstNode());
				}
			}
			//[外带的指针，传播规则]
			// p = &o,如果o是tainted，那么p也应该是tainted
			else if (AddrSVFGNode::classof(succNode))
			{
				AddrSVFGNode *addrSVFGNode = (AddrSVFGNode *)succNode;
				const PAGNode *srcPAGNode = addrSVFGNode->getPAGSrcNode();
				if (inSet(srcPAGNode, taintPointers))
				{
					taintPointers.insert(addrSVFGNode->getPAGDstNode());
				}
			}
			else
			{
#if DEBUG
				cout << "unsupported instruction:" << succNode->toString() << endl;
#endif
			}
			if (visited.find(succNode) == visited.end())
			{
				visited.insert(succNode);
				worklist.push(succNode);
			}
		}
	}
}

void ELA::getNextLoadNodes(NodeID startIcfgNodeId, NodeID pagNodeId, Set<NodeID> &loadTaints)
{
	ICFGNode *iNode = icfg->getGNode(startIcfgNodeId);
	FIFOWorkList<const ICFGNode *> worklist;
	Set<const ICFGNode *> visited;
	worklist.push(iNode);
	while (!worklist.empty())
	{
		const ICFGNode *iNode = worklist.pop();
		for (ICFGNode::const_iterator it = iNode->OutEdgeBegin(), eit =
																	  iNode->OutEdgeEnd();
			 it != eit; ++it)
		{
			ICFGEdge *edge = *it;
			ICFGNode *succNode = edge->getDstNode();
			if (visited.find(succNode) == visited.end())
			{
				visited.insert(succNode);
				worklist.push(succNode);
				if (IntraICFGNode::classof(succNode))
				{
					IntraICFGNode *intraICFGNode = (IntraICFGNode *)succNode;
					if (LoadInst::classof(intraICFGNode->getInst()))
					{
						LoadInst *loadInst = (LoadInst *)intraICFGNode->getInst();

						if (pag->getValueNode(loadInst->getOperand(0)) == pagNodeId)
						{
							loadTaints.insert(pag->getValueNode(loadInst));
						}
					}
				}
			}
		}
	}
}

void ELA::findSources()
{
	std::string keywords[] = {
		"user",
		"password",
		"passwd",
		"pwd",
		"birthday",
		"mail",
		"relationship",
		"phone",
		"gps",
		"zip",
		"secret",
		"credential",
		"private",
		"encrypt",
		"decrypt",
		"key",
		"aes",
		"des"};

	// std::vector<SVF::GenericVFGTy::iterator> datas[THREAD_NUM];
	//  int i = 0;
	//  for (auto it = svfg->begin(); it != svfg->end(); ++it)
	//  {
	//      datas[i % THREAD_NUM].push_back(it);
	//      i++;
	//  }

	std::vector<const VFGNode *> datas[THREAD_NUM];

	int i = 0;
	for (auto item : svfg->getMyNodes())
	{
		datas[i % THREAD_NUM].push_back(item);
		i++;
	}

	std::vector<std::thread> threads;
	for (int i = 0; i < THREAD_NUM; ++i)
	{
		threads.emplace_back(sourceTaskWrapper, datas + i, i);
	}

	for (int i = 0; i < THREAD_NUM; ++i)
	{
		if (threads[i].joinable())
		{
			threads[i].join();
		}
	}

	// std::cout << "main end-------" << std::endl;

	//     std::cout << "sourceNum: " << num-- << endl;

	// SVFGNode *svfgNode = it->second;

	// if (noNeedAnalysis(svfgNode->toString()))
	// {
	//     continue;
	// }

	// if (FormalParmVFGNode::classof(svfgNode) || AddrVFGNode::classof(svfgNode))
	// {
	//     std::string cmdStr = svfgNode->toString();
	//     set<std::string> wordsInVariableName;
	//     std::string variableName = "";
	//     bool flag = false;
	//     std::string word = "";
	//     for (int i = 0; i < cmdStr.length(); i++)
	//     {
	//         if (cmdStr[i] == '%')
	//         {
	//             flag = true;
	//             continue;
	//         }
	//         if (flag && (cmdStr[i] == ' ' || cmdStr[i] == '_'))
	//         {
	//             wordsInVariableName.insert(word);
	//             if (cmdStr[i] == ' ')
	//             {
	//                 flag = false;
	//                 break;
	//             }
	//         }
	//         if (flag && cmdStr[i] != '_')
	//         {
	//             word += tolower(cmdStr[i]);
	//         }

	//         if (flag && cmdStr[i] == '_')
	//         {
	//             word = "";
	//         }
	//         if (flag)
	//         {
	//             variableName += cmdStr[i];
	//         }
	//     }
	//     bool isSensitive = false;
	//     for (auto word : wordsInVariableName)
	//     {
	//         for (auto keyword : keywords)
	//         {
	//             if (difflib::MakeSequenceMatcher<>(keyword, word).ratio() > 0.8)
	//             {
	//                 std::cout << "find sensitive variable: " << word << " in " << variableName << " (hit keyword " << keyword << ")" << endl;
	//                 isSensitive = true;
	//                 break;
	//             }
	//         }
	//         if (isSensitive)
	//         {
	//             break;
	//         }
	//     }
	//     if (isSensitive)
	//     {
	//         std::cout << "======" << endl;
	//         std::cout << svfgNode->toString() << endl;
	//         std::cout << "======" << endl;
	//         if (svfgNode->toString().find("retval") == svfgNode->toString().npos &&
	//             svfgNode->toString().find("filename") == svfgNode->toString().npos)
	//         {
	//             addToSources(svfgNode);
	//         }
	//     }
	// }
	// }
}

void ELA::findSinks()
{

	std::vector<SVF::GenericCallGraphTy::iterator> datas[THREAD_NUM];
	auto hash = std::hash<std::string>();
	int i = 0;
	for (auto it = callgraph->begin(), iEnd = callgraph->end(); it != iEnd; it++)
	{
		i += 1;
		datas[i % THREAD_NUM].push_back(it);
	}
	std::vector<std::thread> threads;
	for (int i = 0; i < THREAD_NUM; ++i)
	{
		threads.emplace_back(sinkTaskWrapper, datas + i, i);
	}

	for (int i = 0; i < THREAD_NUM; ++i)
	{
		if (threads[i].joinable())
		{
			threads[i].join();
		}
	}

	// merge sources
	for (int i = 0; i < THREAD_NUM; i++)
	{
		for (auto node : sourceArr[i])
		{
			addToSources(node);
		}
	}

	// merge sinks
	for (int i = 0; i < THREAD_NUM; i++)
	{
		for (auto node : sinkArr[i])
		{
			addToSinks(node);
		}
	}
}
// printSinks();
// }
//         else if (IntraICFGNode::classof(iNode))
//         {
//             // IntraBlockNode* intraICFGNode = (IntraBlockNode*)iNode;
//             // if(GetElementPtrInst::classof(intraICFGNode->getInst())){
//             //     for(auto vfgNode : intraICFGNode->getVFGNodes()){
//             //         if(GepVFGNode::classof(vfgNode)){
//             //             GepVFGNode* gepVFGNode = (GepVFGNode*)vfgNode;
//             //             NodeID src = gepVFGNode->getPAGSrcNodeID();
//             //             auto allocsites = ander->getPts(src);
//             //             for(auto site : allocsites){
//             //                 cout << pag->getGNode(site)->toString() << endl;
//             //                 auto v = pag->getGNode(site)->getValue();
//             //                 if(AllocaInst::classof(v)){
//             //                     AllocaInst* allocaInst = (AllocaInst*)v;
//             //                     // IntegerType::classof(allocaInst->getArraySize()->getType())
//             //                     allocaInst->print(errs());
//             //                     auto res = dyn_cast<ConstantInt>(allocaInst->getArraySize());
//             //                     cout << res->getZExtValue() << endl;

//             //                 }else{
//             //                     cout << "not allocaInst!" << endl;
//             //                 }
//             //             }

//             //         }else{
//             //             cout << "not GepVFGNode" << endl;
//             //         }
//             //     }
//             // }
//         }
//     }
// printSinks();
// }
// void ELA::backwardTracking()
// {
//     for (auto svfgNodeId : sinks)
//     {
//         auto svfgNode = svfg->getGNode(svfgNodeId);
//         if (StoreSVFGNode::classof(svfgNode))
//         {
//             auto storeSVFGNode = (StoreSVFGNode *)svfgNode;
//             auto srcPagId = storeSVFGNode->getPAGSrcNodeID();
//             //一个sink点,eg store(src,dst)，可能有多条incoming的direct边，
//             //需要过滤掉dst关联的direct边
//             for (auto it = storeSVFGNode->directInEdgeBegin(), end = storeSVFGNode->directInEdgeEnd(); it != end; it++)
//             {
//                 auto preNode = (SVFGNode *)(*it)->getSrcNode();
//                 // get pag node from preNode
//                 auto value = preNode->getValue();
//                 if (!value)
//                 {
// #if DEBUG
//                     cout << "getValue() is null:" << preNode->toString() << endl;
// #endif
//                     continue;
//                 }
//                 auto tmpPagId = pag->getValueNode(value);
//                 if ((*it)->isDirectVFGEdge() && srcPagId == tmpPagId)
//                 {
// #if DEBUG
//                     cout << "处理:" << preNode->toString() << endl;
// #endif
//                     std::set<const SVFGNode *> visited = {storeSVFGNode};
//                     std::vector<const SVFGNode *> path = {storeSVFGNode};
//                     DFS(visited, path, preNode);
//                 }
//             }
//         }
//     }
// }

void ELA::backwardTracking()
{

	// cout << "进行可达性分析" << endl;
	// for (auto sink : sinks)
	// {
	//     for (auto source : sources)
	//     {

	//         bool reachable = false;
	//         FIFOWorkList<SVFGNode *> worklist;
	//         Set<SVFGNode *> visited;
	//         worklist.push(sink);
	//         /// Traverse along VFG
	//         while (!worklist.empty())
	//         {
	//             const SVFGNode *svfgNode = worklist.pop();

	//             if (svfgNode == source)
	//             {
	//                 cout << "=============可达============" << endl;
	//                 cout << source->toString() << endl;
	//                 cout << sink->toString() << endl;
	//                 cout << "===========================" << endl;
	//                 reachable = true;
	//                 break;
	//             }

	//             for (SVFGNode::const_iterator it = svfgNode->InEdgeBegin(), eit =
	//                                                                             svfgNode->InEdgeEnd();
	//                  it != eit; ++it)
	//             {
	//                 SVFGEdge *edge = *it;
	//                 SVFGNode *succNode = edge->getSrcNode();
	//                 if (visited.find(succNode) == visited.end())
	//                 {
	//                     visited.insert(succNode);
	//                     worklist.push(succNode);
	//                 }
	//             }
	//         }
	//     }
	// }
	//
	// cout << "可达，进行路径分析" << endl;
	std::stringstream ss;
	ss << "\n#######################################KEY INFO##############################################" << endl;
	ss << "NUM OF SOURCES: " << sources.size() << "\n";
	ss << "NUM OF SINKS: " << sinks.size() << "\n";
	ss << "SOURCES LIST:"
	   << "\n";
	for (auto source : sources)
	{
		ss << "source: " << source->toString() << endl;
	}
	ss << "SINKS LIST:" << endl;
	for (auto sink : sinks)
	{
		ss << "sink: " << sink->toString() << endl;
	}
	ss << "############################################################################################" << endl;
	print(ss);

	int sourcesNum = sources.size();
	if (sourcesNum > 0 and sinks.size() > 0)
	{

		std::vector<const SVFGNode *> datas[THREAD_NUM];
		// bool reverse = sources.size() > sinks.size() ? true : false;
		bool reverse = true;
		int i = 0;
		if (reverse)
		{
			for (auto sink : sinks)
			{
				datas[i % THREAD_NUM].push_back(sink);
				i += 1;
			}
		}
		else
		{
			for (auto source : sources)
			{
				datas[i % THREAD_NUM].push_back(source);
				i += 1;
			}
		}

		std::vector<std::thread> threads;
		for (int i = 0; i < THREAD_NUM; ++i)
		{
			threads.emplace_back(backwardTaskWrapper, datas + i, i, reverse, 20);
		}

		for (int i = 0; i < THREAD_NUM; ++i)
		{
			if (threads[i].joinable())
			{
				threads[i].join();
			}
		}
	}
}

void ELA::printPath(std::vector<const SVFGNode *> &path)
{
	std::stringstream ss;
	ss << "\n######################PRIVACY LEAKAGE##############################\n";
	for (auto node : path)
	{
		ss << node->toString() << "\n";
		ss << "-------------->";
	}
	ss << "\n##################################################################\n";
	print(ss);
}

// void ELA::DFS(std::set<const SVFGNode *> &visited, std::vector<const SVFGNode *> &path, const SVFGNode *src, bool reverse, int maxDepth)
// {
// #if DEBUG
//     cout << "processing..." << endl;
//     cout << src->toString() << endl;
// #endif
//     if (reverse)
//     {
//         if (sourceMapping.find(src) != sourceMapping.end())
//         {
//             SVFUtil::errs() << bugMsg1("privacy leak found :");
//             // std::cout << "privacy leak found :" << endl;
//             printPath(path);
//             std::cout << src->toString() << endl;
//             std::cout << endl
//                       << endl;
//             return;
//         }
//     }
//     else
//     {
//         if (sinkMapping.find(src) != sinkMapping.end())
//         {
//             SVFUtil::errs() << bugMsg1("privacy leak found :");
//             // std::cout << "privacy leak found :" << endl;
//             printPath(path);
//             std::cout << src->toString() << endl;
//             std::cout << endl
//                       << endl;
//             return;
//         }
//     }

//     if (maxDepth <= 0)
//     {
//         return;
//     }

//     auto edges = reverse ? src->getInEdges() : src->getOutEdges();
//     if (edges.size() == 0)
//     {
//         return;
//     }

//     path.push_back(src);
//     visited.insert(src);
//     maxDepth--;
//     // cout << maxDepth << " ";
//     for (auto edge : edges)
//     {
//         auto nextNode = reverse ? edge->getSrcNode() : edge->getDstNode();
//         if (visited.find(nextNode) == visited.end())
//         {

//             DFS(visited, path, nextNode, reverse, maxDepth);
//         }
//     }
//     path.pop_back();
//     visited.erase(src);
//     maxDepth++;
// }

void ELA::DFS(Set<const SVFGNode *> &visited, std::vector<const SVFGNode *> &path, const SVFGNode *src, const SVFGNode *dst)
{
#if DEBUG
	cout << "processing..." << endl;
	cout << src->toString() << endl;
#endif

	if (!src)
	{
		return;
	}

	if (src == dst)
	{
		path.push_back(src);
		printPath(path);
		return;
	}

	path.push_back(src);
	visited.insert(src);
	int minBudget = -2;
	SVFGNode *minBudgetNode = nullptr;
	for (auto edge : src->getInEdges())
	{
		int curBudget = getBudget(edge->getSrcNode(), dst);
		if (curBudget == -1)
		{
			continue;
		}

		if (minBudget == -2)
		{
			minBudget = curBudget;
			minBudgetNode = edge->getSrcNode();
		}
		else
		{
			if (minBudget > curBudget)
			{
				minBudget = curBudget;
				minBudgetNode = edge->getSrcNode();
			}
		}
	}

	if (minBudget == -2)
	{
		return;
	}

	if (visited.find(minBudgetNode) == visited.end())
	{
		// cout << "select min budget node!" << endl;
		DFS(visited, path, minBudgetNode, dst);
	}
}

void ELA::printICFGTraverseTime() {}

static llvm::cl::opt<std::string> InputFilename(llvm::cl::Positional,
												llvm::cl::desc("<input bitcode>"), llvm::cl::init("-"));

int main(int argc, char **argv)
{
	clock_t start, end;
	start = clock();
	std::cout << "start..." << endl;

#if REGRESSION
	regressionTest();
#endif
	// 1. sgx_wechat_app
	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod2/sgx_wechat_app.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod2/sgx_wechat_app.config");
	// 2. sgx-based-mix-networks
	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod2/sgx-based-mix-networks.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod2/sgx-based-mix-networks.config");
	// 3. sgx-dnet
	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod2/sgx-dnet.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod2/sgx-dnet.config");
	// 4. sgx-aes-gcm
	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod/sgx-aes-gcm.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/src/config/sgx-aes-gcm.config");
	// 5. password-manager
	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod2/password-manager.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod2/password-manager.config");
	// 6. TACIoT
	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod/TACIoT.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/src/config/TACIoT.config");
	// 7. Town-Crier
	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod/Town-Crier.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/src/config/Town-Crier.config");
	// 8. SGX_SQLite
	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod/SGX_SQLite.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/src/config/SGX_SQLite.config");

	// 9. mbedtls_SGX
	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod/mbedtls_SGX.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/src/config/mbedtls_SGX.config");

	// 10. Fidelius
	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod2/Fidelius.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod2/Fidelius.config");

	// 11. BiORAM-SGX
	//  std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod2/BiORAM-SGX.ll",
	//  "/home/yang/ELA/testcase/prod2/BiORAM-SGX-dataowner_data.ll"};
	//  ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod2/BiORAM-SGX.config");

	// 12. PrivacyGuard
	//  std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod/PrivacyGuard/CEE.ll",
	//  "/home/yang/ELA/testcase/prod/PrivacyGuard/DataBroker.ll",
	//  "/home/yang/ELA/testcase/prod/PrivacyGuard/Enclave_testML.ll",
	//  "/home/yang/ELA/testcase/prod/PrivacyGuard/iDataAgent.ll"};
	//  ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod/config/PrivacyGuard.config");

	// 12. talos
	//  std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod/TaLoS.ll"};
	//  ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod/config/talos.config");

	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod2/BiORAM-SGX.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod2/BiORAM-SGX.config");

	// std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod2/BiORAM-SGX-dataowner_data.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod2/BiORAM-SGX-dataowner_data.config");

	// ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod2/BiORAM-SGX.config");

	// std::vector<std::string> mnv = {"/home/yang/ELA/2.ll"};
	// ELA *ela = new ELA(mnv, "/home/yang/ELA/2.config");

	// SGX-Tor
	//  std::vector<std::string> mnv = {"/home/yang/ELA/testcase/prod2/SGX-Tor.ll"};
	//  ELA *ela = new ELA(mnv, "/home/yang/ELA/testcase/prod2/SGX-Tor.config");
	{
		timer total_timer("Total");
		int arg_num = 0;
		char **arg_value = new char *[argc];
		std::vector<std::string> moduleNameVec;
		SVFUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
		llvm::cl::ParseCommandLineOptions(arg_num, arg_value, "Whole Program Points-to Analysis\n");
		string configPath = moduleNameVec[0].substr(0, moduleNameVec[0].find(".ll")) + ".config";
		std::cout << "configPath: " << configPath << endl;
		ela = new ELA(moduleNameVec, configPath);
		{
			timer source_timer("find sources");
			// ela->findSources();
		}
		{
			timer sink_timer("find sinks");
			// ela->findSinks();
		}
		{
			timer backward_timer("backward");
			// ela->backwardTracking();
		}

		ela->findMallocNotCheck();

		std::stringstream ss;
		ss << moduleNameVec[0] << " finished!\n";
		print(ss);
	}
	return 0;
}
