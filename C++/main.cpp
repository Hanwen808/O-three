#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string.h>
#include <vector>

#include "Headers/Lean.h"
#include "Headers/Sketch.h"
#include "Headers/LeanCF.h"
#include "Headers/O3Skt.h"
#define KEY_LEN 16

using namespace std;

uint32_t convertIPv4ToUint32(char* ipAddress) {
    uint32_t result = 0;
    int octet = 0;
    char ipCopy[KEY_LEN];
    strncpy(ipCopy, ipAddress, sizeof(ipCopy) - 1);
    ipCopy[sizeof(ipCopy) - 1] = '\0';
    char* token = strtok(ipCopy, ".");
    while (token != nullptr) {
        octet = std::stoi(token);
        result = (result << 8) + octet;
        token = strtok(nullptr, ".");
    }
    return result;
}

uint64_t combineFlowKey(uint32_t src_ip, uint32_t dst_ip) {
    uint64_t result = static_cast<uint64_t>(src_ip) << 32 | dst_ip;
    return result;
}

// Updating Sketch and testing the processing throughput.
void processPackets(Sketch* skt, vector<pair<uint64_t, uint32_t>>& dataset) {
    clock_t start = clock(); // The start time of processing packet stream
    for (int i = 0; i < dataset.size(); i++) {
        skt->update(dataset[i].first, dataset[i].second);
    }
    clock_t current = clock(); // The end time of processing packet stream
    cout << dataset.size() << " lines: have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds" << endl;
    double throughput = (dataset.size() / 1000000.0) / (((double)current - start) / CLOCKS_PER_SEC);
    cout << "throughput: " << throughput << "Mpps" << endl;
}

void getDataSet(string dataDir, unsigned int numOfMinutes, vector<pair<uint64_t, uint32_t>>& dataset,
                unordered_map<uint64_t, uint32_t>& realFlowInfo)
{
    char dataFileName[20]; // The filename of dataset
    uint64_t flowId;          // flow key
    uint32_t src_ip_int, dst_ip_int, seqno_int;
    string line, source, destination, seqno, _time;
    clock_t start = clock();
    for (unsigned int i = 0; i < numOfMinutes; i++) {
        sprintf(dataFileName, "%02d.txt ", i);
        string oneDataFilePath = "../data/00.txt"; // Organize a complete filename.
        cout << oneDataFilePath << endl;
        fstream fin(oneDataFilePath);
        std::unordered_map<uint64_t, uint32_t> flow_max_seq_dict;
        bool is_first = true;
        while (fin.is_open() && fin.peek() != EOF) {
            getline(fin, line); // each line of dataset is consist of three fields: source address, destination address and destination port
            stringstream ss(line.c_str());
            // Build a flow element
            if (is_first) {
                is_first = false;
                continue;
            }
            ss >> source >> destination >> seqno >> _time;
            src_ip_int = convertIPv4ToUint32((char*) source.c_str());
            dst_ip_int = convertIPv4ToUint32((char*) destination.c_str());
            flowId = combineFlowKey(src_ip_int, dst_ip_int);
            seqno_int = static_cast<uint32_t>(std::atoi((char*) seqno.c_str()));
            dataset.push_back(make_pair(flowId, seqno_int));
            if (flow_max_seq_dict.find(flowId) == flow_max_seq_dict.end()) {
                flow_max_seq_dict[flowId] = seqno_int;
            } else {
                if (seqno_int > flow_max_seq_dict[flowId])
                    flow_max_seq_dict[flowId] = seqno_int;
                else {
                    if (realFlowInfo.find(flowId) == realFlowInfo.end()) {
                        realFlowInfo[flowId] = 1;
                    } else
                        realFlowInfo[flowId] += 1;
                }
            }
            if (dataset.size() % 5000000 == 0) {
                clock_t current = clock();
                cout << "have added " << dataset.size() << " packets, have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds." << endl;
            }
        }
        if (!fin.is_open()) {
            cout << "dataset file " << oneDataFilePath << "closed unexpectedlly"<<endl;
            exit(-1);
        }else
            fin.close();
    }
    clock_t current = clock();
    cout << "have added " << dataset.size() << " packets, have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds" << endl;
}

void saveResults(string outputFilePath, Sketch* skt, unordered_map<uint64_t, uint32_t>& realFlowInfo, uint32_t T) {
    ofstream fout;
    std::unordered_set<uint64_t> pred_chaos = skt->get_result(T);
    std::unordered_set<uint64_t> real_chaos;
    std::vector<double> re_vector;
    auto iter = realFlowInfo.begin();
    fout.open(outputFilePath, ios::out);
    while (iter != realFlowInfo.end()) {
        int realo3 = iter->second;
        if (realo3 >= T) {
            real_chaos.insert(iter->first);
            int estimatedo3 = skt->estimate(iter->first);
            re_vector.push_back((1.0 * abs(estimatedo3 - realo3)) / (1.0 * realo3));
        }
        iter++;
    }
    std::unordered_set<uint64_t> TP_set;
    std::unordered_set<uint64_t> FP_set;
    std::unordered_set<uint64_t> FN_set;
    for (auto iter = real_chaos.begin(); iter != real_chaos.end(); iter ++) {
        if (pred_chaos.find(*iter) != pred_chaos.end())
            TP_set.insert(*iter);
        else
            FN_set.insert(*iter);
    }
    for (auto iter = pred_chaos.begin(); iter != pred_chaos.end(); iter ++) {
        if (real_chaos.find(*iter) == real_chaos.end())
            FP_set.insert(*iter);
    }
    double precision = (1.0 * TP_set.size()) / (1.0 * TP_set.size() + 1.0 * FP_set.size());
    double recall = ((1.0 * TP_set.size()) / (1.0 * TP_set.size() + 1.0 * FN_set.size()));
    double F1_score = (2 * precision * recall) / (precision + recall);

    double _sum = 0.0, _cnt = 0.0;
    for (auto iter = re_vector.begin(); iter != re_vector.end(); iter ++) {
        _sum += *iter;
        _cnt ++;
    }

    _sum = _sum / _cnt;

    fout << "Precision: " << precision << ", recall: " << recall << ", F1 score: " << F1_score << ", ARE: " << _sum << "\n";

    if (!fout.is_open())
        cout << outputFilePath << " closed unexpectedlly";
    else
        fout.close();
    cout << "";
}

int main() {
    //prepare the dataset
    cout << "prepare the dataset" << endl;
    string dataDir = R"(../data/)";
    unsigned int numOfMinutes = 1;
    vector<pair<uint64_t, uint32_t >> dataset;
    unordered_map<uint64_t, uint32_t> realFlowInfo;
    getDataSet(dataDir, numOfMinutes, dataset, realFlowInfo);
    cout << endl;
    uint32_t m2 = 100000;
    uint32_t mem = 3096 * 1024;
    uint32_t m1 = static_cast<uint32_t>((1.0 * (mem - m2 * 12)) / 8.0);
    std::cout << m1 << " " << m2 << endl;
    Sketch *skt = new LeanCF(m1, m2);

    /*uint32_t mem = 128;
    double ratio = 0.7;
    uint32_t d = 4;
    uint32_t stage1_mem = static_cast<uint32_t>(mem * ratio * 1024);
    uint32_t stage2_mem = static_cast<uint32_t>(mem * (1 - ratio) * 1024);
    uint32_t m1 = stage1_mem / d / 16;
    uint32_t m2 = static_cast<uint32_t>((1.0 * stage2_mem) / 12.5);
    std::cout << m1 << " " << m2 << std::endl;
    Sketch *skt = new O3Skt(d, m1, m2);*/

    cout << endl;
    cout << "Start processing..." << endl;
    processPackets(skt, dataset);
    //save the result in files
    cout << endl;
    cout << "save the result in txt ..." << endl;
    string outputFilePath = "../record/128KB.txt";
    saveResults(outputFilePath, skt, realFlowInfo, 50611);
    return 0;
}
