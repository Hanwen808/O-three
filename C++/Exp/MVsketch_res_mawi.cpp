#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string.h>
#include <vector>

#include "../Headers/Sketch.h"
#include "../Headers/MVSketch.h"
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
void processPackets(Sketch* skt, vector<pair<KEY, uint32_t>>& dataset, double* res_throughput) {
    clock_t start = clock(); // The start time of processing packet stream
    for (int i = 0; i < dataset.size(); i++) {
        skt->update(dataset[i].first, dataset[i].second);
    }
    clock_t current = clock(); // The end time of processing packet stream
    //cout << dataset.size() << " lines: have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds" << endl;
    double throughput = (dataset.size() / 1000000.0) / (((double)current - start) / CLOCKS_PER_SEC);
    //cout << "throughput: " << throughput << "Mpps" << endl;
    *res_throughput = throughput;
}

void testQuery(Sketch* skt, vector<pair<KEY, uint32_t>>& dataset, double* res_response_time) {
    clock_t start = clock(); // The start time of processing packet stream
    for (int i = 0; i < dataset.size(); i++) {
        skt->estimate(dataset[i].first);
    }
    clock_t current = clock(); // The end time of processing packet stream
    double response_time = (((double)current - start) / CLOCKS_PER_SEC) / dataset.size();
    //cout << dataset.size() << " lines: have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds" << endl;
    //double throughput = (dataset.size() / 1000000.0) / (((double)current - start) / CLOCKS_PER_SEC);
    //cout << "response time: " << response_time << " seconds" << endl;
    *res_response_time = response_time;
}

// void querySpec(uint64_t key, Sketch* skt, uint32_t real) {
//    std::cout << skt->estimate(key) << std::endl; 
//     uint32_t est = skt->estimate(key);
//     std::cout << (real * 1.0 - est * 1.0) / (0.05 * 5131256);
// }

void getDataSet(string dataDir, unsigned int numOfMinutes, vector<pair<KEY, uint32_t>>& dataset,
                unordered_map<KEY, uint32_t, KEYHash, KEYEqual>& realFlowInfo)
{
    char dataFileName[32]; // The filename of dataset
    KEY flowId;          // flow key
    uint32_t src_ip_int, dst_ip_int, seqno_int;
    string line, source, destination, seqno, sport, dport;
    clock_t start = clock();
    for (unsigned int i = 0; i < numOfMinutes; i++) {
        sprintf(dataFileName, "%02d.txt ", i);
        string oneDataFilePath = "../data/mawi_five_tuple.txt"; // Organize a complete filename.
        cout << oneDataFilePath << endl;
        fstream fin(oneDataFilePath);
        std::unordered_map<KEY, uint32_t, KEYHash, KEYEqual> flow_max_seq_dict;
        bool is_first = true;
        while (fin.is_open() && fin.peek() != EOF) {
            getline(fin, line); // each line of dataset is consist of three fields: source address, destination address and destination port
            stringstream ss(line.c_str());
            // Build a flow element
            if (is_first) {
                is_first = false;
                continue;
            }
            ss >> source >> sport >> destination >> dport >> seqno;
            src_ip_int = convertIPv4ToUint32((char*) source.c_str());
            dst_ip_int = convertIPv4ToUint32((char*) destination.c_str());
            //flowId = combineFlowKey(src_ip_int, dst_ip_int);
            flowId.src_ip = src_ip_int;
            flowId.dst_ip = dst_ip_int;
            flowId.sport = static_cast<uint16_t>(std::atoi((char*) sport.c_str()));
            flowId.dport = static_cast<uint16_t>(std::atoi((char*) dport.c_str()));
            // if (source == "189.17.30.10" && destination == "199.124.196.113") {
            //      std::cout << flowId << std::endl;
            // }
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

void saveResults(Sketch* skt, unordered_map<KEY, uint32_t, KEYHash, KEYEqual>& realFlowInfo, uint32_t T, double* F1score, double* Precision, double* Recall, double* ARE) {
    std::unordered_set<KEY, KEYHash, KEYEqual> pred_chaos = skt->get_result(T);
    std::unordered_set<KEY, KEYHash, KEYEqual> real_chaos;
    std::vector<double> re_vector;
    auto iter = realFlowInfo.begin();
    uint32_t sum_real_chaotic = 0;
    while (iter != realFlowInfo.end()) {
        int realo3 = iter->second;
        if (realo3 >= T) {
            sum_real_chaotic += realo3;
            real_chaos.insert(iter->first);
            int estimatedo3 = skt->estimate(iter->first);
            re_vector.push_back((1.0 * abs(estimatedo3 - realo3)) / (1.0 * realo3));
        }
        iter++;
    }
    //std::cout << "real chaotic o3 is " << sum_real_chaotic << std::endl;
    std::unordered_set<KEY, KEYHash, KEYEqual> TP_set;
    std::unordered_set<KEY, KEYHash, KEYEqual> FP_set;
    std::unordered_set<KEY, KEYHash, KEYEqual> FN_set;
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
    *F1score = F1_score;
    *Precision = precision;
    *Recall = recall;
    *ARE = _sum;
}

int main() {
    //prepare the dataset
    cout << "prepare the dataset" << endl;
    string dataDir = R"(./data/)";
    unsigned int numOfMinutes = 1;
    vector<pair<KEY, uint32_t >> dataset;
    unordered_map<KEY, uint32_t, KEYHash, KEYEqual> realFlowInfo;
    getDataSet(dataDir, numOfMinutes, dataset, realFlowInfo);
    cout << endl;

    std::vector<uint32_t> mems{32, 64, 128, 256, 512};
    for (auto iter = mems.begin(); iter != mems.end(); iter ++) {
        uint32_t mem = *iter;
        double ratio1 = 0.5;
        uint32_t stage1_mem = static_cast<uint32_t>(mem * ratio1 * 1024);
        uint32_t stage2_mem = static_cast<uint32_t>(mem * (1-ratio1) * 1024);
        uint32_t M = stage1_mem / 16;
        uint32_t d = 3;
        uint32_t w = stage2_mem / d / 20;
        int EXP_num = 10;
        double res_throughput[EXP_num], res_response_time[EXP_num];
        double F1score[5][EXP_num], Precision[5][EXP_num], Recall[5][EXP_num], ARE[5][EXP_num];
        memset(res_throughput, 0.0, sizeof(double) * EXP_num);
        memset(res_response_time, 0.0, sizeof(double) * EXP_num);
        memset(F1score, 0.0, sizeof(double) * EXP_num * 5);
        memset(Precision, 0.0, sizeof(double) * EXP_num * 5);
        memset(Recall, 0.0, sizeof(double) * EXP_num * 5);
        memset(ARE, 0.0, sizeof(double) * EXP_num * 5);
        for (int jj = 0; jj < EXP_num; jj++) {
            Sketch *skt = new MVSketch(M, d, w);
            processPackets(skt, dataset, &res_throughput[jj]);
            testQuery(skt, dataset, &res_response_time[jj]);
            std::vector<uint32_t> thresholds{777, 2331, 3885, 5439, 6993};
            int my_cursor = 0;
            for (auto iter2 = thresholds.begin(); iter2 != thresholds.end(); iter2 ++, my_cursor ++) {
                saveResults( skt, realFlowInfo, *iter2, &F1score[my_cursor][jj], &Precision[my_cursor][jj], &Recall[my_cursor][jj], &ARE[my_cursor][jj]);
            }
        }
        int idxmapThresholds[5];
        idxmapThresholds[0] = 777;
        idxmapThresholds[1] = 2331;
        idxmapThresholds[2] = 3885;
        idxmapThresholds[3] = 5439;
        idxmapThresholds[4] = 6993;
        for (int file_idx = 0; file_idx < 5; file_idx ++) {
            ofstream fout;
            string outputFilePath = "../MVSketch_MAWI/mvsketch_" + std::to_string(*iter) + "_" + std::to_string(idxmapThresholds[file_idx]) + ".txt";
            fout.open(outputFilePath, ios::out);
            double avg_throughput = 0.0, avg_response_time = 0.0, avg_precision = 0.0, avg_recall = 0.0, avg_f1score = 0.0, avg_are = 0.0;
            for (int jjj = 0; jjj < EXP_num; jjj++) {
                avg_throughput += res_throughput[jjj];
                avg_response_time += res_response_time[jjj];
                avg_precision += Precision[file_idx][jjj];
                avg_recall += Recall[file_idx][jjj];
                avg_f1score += F1score[file_idx][jjj];
                avg_are += ARE[file_idx][jjj];
            }
            avg_throughput = avg_throughput / (1.0 * EXP_num);
            avg_response_time = avg_response_time / (1.0 * EXP_num);
            avg_precision = avg_precision / (1.0 * EXP_num);
            avg_recall = avg_recall / (1.0 * EXP_num);
            avg_f1score = avg_f1score / (1.0 * EXP_num);
            avg_are = avg_are / (1.0 * EXP_num);
            fout << "Precision: " << avg_precision << ", Recall: " << avg_recall << ", F1 score: " << avg_f1score << ", ARE: " << avg_are << ", Throughput: " << avg_throughput << ", Response Time: " << avg_response_time << "\n";
            fout.close();
        }
    }
    return 0;
}
