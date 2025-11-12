// realistic_auth_sim.cpp
// Compile: g++ -std=c++17 verbose.cpp -lcryptopp -O2 -pthread -o verbose
// run using ./verbose
// listing all the optional params -> ./verbose --nodes 200 --workers 4 --tamper-percent 1 --payload-bytes 512 --node-jitter 100 --net-ta-node 10 50 --net-node-mw 10 50 --db-delay 20 60 --fail-percent 3 --out results.csv

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <numeric>
#include <random>
#include <cstring>
#include <cstdlib>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>

using std::string;
using std::cout;
using std::cerr;
using std::endl;
using CryptoPP::byte;

// ---------- Helpers: hex encode/decode ----------
string toHex(const string &input) {
    std::string output;
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(output), false));
    return output;
}

string fromHex(const string &hex) {
    std::string output;
    CryptoPP::StringSource ss(hex, true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(output)));
    return output;
}

// ---------- Key derivation (SHA256 -> take first 16 bytes for AES-128) ----------
CryptoPP::SecByteBlock deriveKey(const string &passphrase) {
    byte digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::SHA256().CalculateDigest(digest, (const byte*)passphrase.data(), passphrase.size());
    CryptoPP::SecByteBlock key(16);
    std::copy(digest, digest + 16, key.begin());
    return key;
}

// ---------- AES-CBC encrypt/decrypt with random IV ----------
string aesEncryptHex(const CryptoPP::SecByteBlock &key, const string &plain) {
    CryptoPP::AutoSeededRandomPool rng;
    byte iv[CryptoPP::AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));
    std::string cipher;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    CryptoPP::StringSource ss(plain, true,
        new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(cipher))
    );
    string ivhex = toHex(string((const char*)iv, sizeof(iv)));
    string chex  = toHex(cipher);
    return ivhex + ":" + chex;
}

string aesDecryptHex(const CryptoPP::SecByteBlock &key, const string &combined) {
    auto pos = combined.find(':');
    if (pos == string::npos) throw std::runtime_error("Bad ciphertext format");
    string ivhex = combined.substr(0, pos);
    string chex  = combined.substr(pos + 1);
    string iv = fromHex(ivhex);
    string cipher = fromHex(chex);

    std::string recovered;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), (const byte*)iv.data());
    CryptoPP::StringSource ss(cipher, true,
        new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(recovered))
    );
    return recovered;
}

// ---------- Random token generator (hex string) ----------
string genTokenHex(size_t bytes = 16) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string raw(bytes, '\0');
    rng.GenerateBlock((byte*)raw.data(), raw.size());
    return toHex(raw);
}

// ---------- Simulated pre-shared keys & ids ----------
const string NODE_ID_BASE = "node-";
CryptoPP::SecByteBlock KEY_TA_NODE;
CryptoPP::SecByteBlock KEY_NODE_MW;
CryptoPP::SecByteBlock KEY_TA_MW;

// ---------- TA issues per-request tokens (stateless helper) ----------
struct IssuedTokens {
    string token_plain;
    string enc_for_node;
    string enc_for_mw;
};

IssuedTokens TA_issue_tokens_for_node(const string &node_id) {
    string token = genTokenHex(16);
    string payload_for_node = "NODE_ID:" + node_id + ";TOKEN:" + token;
    string payload_for_mw   = "MW_EXPECTS_NODE:" + node_id + ";TOKEN:" + token;
    string enc_node = aesEncryptHex(KEY_TA_NODE, payload_for_node);
    string enc_mw   = aesEncryptHex(KEY_TA_MW, payload_for_mw);
    return { token, enc_node, enc_mw };
}

// ---------- Config ----------
struct Config {
    int nodes = 100;                  // Number of simulated nodes
    int workers = 2;                  // Simulate weak CPU: only 2 concurrent threads
    double tamper_percent = 0.0;      // No tampering unless you want to test it
    int payload_bytes = 500;          // Typical small IoT/LAN message
    int node_start_jitter_ms = 50;    // Small jitter in node start times
    int net_delay_ta_node_min = 5, net_delay_ta_node_max = 20;    // LAN: low network delay (ms)
    int net_delay_node_mw_min = 5, net_delay_node_mw_max = 20;    // LAN: low network delay (ms)
    int db_delay_min = 10, db_delay_max = 30;                     // Simulate slow DB or processing (ms)
    double fail_percent = 0.0;         // 2% simulated drop/failure rate
    string out_file = "realistic_perf.csv";
};
bool parse_args(int argc, char** argv, Config &cfg) {
    for (int i=1;i<argc;i++) {
        string a = argv[i];
        if (a=="--nodes" && i+1<argc) { cfg.nodes = std::stoi(argv[++i]); }
        else if (a=="--workers" && i+1<argc) { cfg.workers = std::stoi(argv[++i]); }
        else if (a=="--tamper-percent" && i+1<argc) { cfg.tamper_percent = std::stod(argv[++i]); }
        else if (a=="--payload-bytes" && i+1<argc) { cfg.payload_bytes = std::stoi(argv[++i]); }
        else if (a=="--node-jitter" && i+1<argc) { cfg.node_start_jitter_ms = std::stoi(argv[++i]); }
        else if (a=="--net-ta-node" && i+2<argc) {
            cfg.net_delay_ta_node_min = std::stoi(argv[++i]);
            cfg.net_delay_ta_node_max = std::stoi(argv[++i]);
        }
        else if (a=="--net-node-mw" && i+2<argc) {
            cfg.net_delay_node_mw_min = std::stoi(argv[++i]);
            cfg.net_delay_node_mw_max = std::stoi(argv[++i]);
        }
        else if (a=="--db-delay" && i+2<argc) {
            cfg.db_delay_min = std::stoi(argv[++i]);
            cfg.db_delay_max = std::stoi(argv[++i]);
        }
        else if (a=="--fail-percent" && i+1<argc) { cfg.fail_percent = std::stod(argv[++i]); }
        else if (a=="--out" && i+1<argc) { cfg.out_file = argv[++i]; }
        else if (a=="--help" || a=="-h") {
            return false;
        } else {
            cerr << "Unknown arg: " << a << "\n";
            return false;
        }
    }
    if (cfg.nodes <= 0) cfg.nodes = 1000;
    if (cfg.workers <= 0) cfg.workers = 1;
    if (cfg.tamper_percent < 0) cfg.tamper_percent = 0;
    if (cfg.tamper_percent > 100) cfg.tamper_percent = 100;
    if (cfg.fail_percent < 0) cfg.fail_percent = 0;
    if (cfg.fail_percent > 100) cfg.fail_percent = 100;
    return true;
}

void print_usage(const char* prog) {
    cout << "Usage: " << prog << " [--nodes N] [--workers N] [--tamper-percent P] [--payload-bytes N]\n";
    cout << "       [--node-jitter MS] [--net-ta-node MIN MAX] [--net-node-mw MIN MAX] [--db-delay MIN MAX]\n";
    cout << "       [--fail-percent P] [--out filename]\n";
    cout << "Defaults: nodes=1000 workers=4 tamper-percent=0.0 payload-bytes=256 fail-percent=1.0\n";
    cout << "Example: " << prog << " --nodes 1000 --workers 4 --tamper-percent 5 --payload-bytes 512 --fail-percent 2\n";
}

// ---------- Metrics ----------
struct NodeMetrics {
    int node_index;
    long long total_us = 0;
    bool success = false;
    bool dropped = false;
};

long long median_of_vec(std::vector<long long> v) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    return (n % 2 == 1) ? v[n/2] : ((v[n/2 - 1] + v[n/2]) / 2);
}

// ---------- Worker ----------
void worker_func(std::atomic<int> &counter, const Config &cfg, std::vector<NodeMetrics> &results, std::mutex &res_mutex, std::mt19937 &rng) {
    std::uniform_int_distribution<int> jitter(0, cfg.node_start_jitter_ms);
    std::uniform_int_distribution<int> net_ta_node(cfg.net_delay_ta_node_min, cfg.net_delay_ta_node_max);
    std::uniform_int_distribution<int> net_node_mw(cfg.net_delay_node_mw_min, cfg.net_delay_node_mw_max);
    std::uniform_int_distribution<int> db_delay(cfg.db_delay_min, cfg.db_delay_max);
    std::uniform_real_distribution<double> tamper_unif(0.0, 1.0);
    std::uniform_real_distribution<double> fail_unif(0.0, 1.0);

    while (true) {
        int idx = counter.fetch_add(1);
        if (idx >= cfg.nodes) break;
        NodeMetrics m{};
        m.node_index = idx;
        using clk = std::chrono::high_resolution_clock;
        auto t_start = clk::now();

        // Staggered node start
        std::this_thread::sleep_for(std::chrono::milliseconds(jitter(rng)));

        // Simulate network delay TA -> Node
        std::this_thread::sleep_for(std::chrono::milliseconds(net_ta_node(rng)));

        // Simulate random drop/failure
        if (fail_unif(rng) < (cfg.fail_percent / 100.0)) {
            m.dropped = true;
            auto t_end = clk::now();
            m.total_us = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_start).count();
            std::lock_guard<std::mutex> lg(res_mutex);
            results.push_back(std::move(m));
            continue;
        }

        // TA issues token
        IssuedTokens issued = TA_issue_tokens_for_node(NODE_ID_BASE + std::to_string(idx));

        // Node decrypts
        string decrypted_payload = aesDecryptHex(KEY_TA_NODE, issued.enc_for_node);
        auto p_token = decrypted_payload.find("TOKEN:");
        string token_extracted = (p_token != string::npos) ? decrypted_payload.substr(p_token + 6) : "";

        // Maybe tamper
        if (tamper_unif(rng) < (cfg.tamper_percent / 100.0)) {
            token_extracted = genTokenHex(8);
        }

        // Build and encrypt to MW
        string payload(cfg.payload_bytes, 'A' + (idx % 26));
        string header = "NODE_ID:" + NODE_ID_BASE + std::to_string(idx) + ";TOKEN:" + token_extracted;
        string full_request = "HEADER[" + header + "]|BODY[" + payload + "]";

        // Simulate network delay Node -> MW
        std::this_thread::sleep_for(std::chrono::milliseconds(net_node_mw(rng)));

        string encrypted_for_mw = aesEncryptHex(KEY_NODE_MW, full_request);

        // Middleware decrypt & validate
        string ta_payload_for_mw = aesDecryptHex(KEY_TA_MW, issued.enc_for_mw);
        string ta_token;
        auto p = ta_payload_for_mw.find("TOKEN:");
        if (p != string::npos) ta_token = ta_payload_for_mw.substr(p + 6);

        string node_request_plain = aesDecryptHex(KEY_NODE_MW, encrypted_for_mw);

        // parse header token
        string header_marker = "HEADER[";
        auto hpos = node_request_plain.find(header_marker);
        if (hpos != string::npos) {
            auto hend = node_request_plain.find("]", hpos + header_marker.size());
            if (hend != string::npos) {
                string header_str = node_request_plain.substr(hpos + header_marker.size(), hend - (hpos + header_marker.size()));
                auto tpos = header_str.find("TOKEN:");
                string node_token = (tpos != string::npos) ? header_str.substr(tpos + 6) : "";
                m.success = (node_token == ta_token);
            }
        }

        // Simulate DB write delay
        std::this_thread::sleep_for(std::chrono::milliseconds(db_delay(rng)));

        auto t_end = clk::now();
        m.total_us = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_start).count();

        std::lock_guard<std::mutex> lg(res_mutex);
        results.push_back(std::move(m));
    }
}

// ---------- CSV + summary helpers ----------
std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&now_c);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void append_perf_csv(int nodes, int workers, long long avg_us, long long min_us, long long max_us, long long med_us, double success_pct, double drop_pct, double wall_time_s, const string &filename) {
    bool newFile = false;
    {
        std::ifstream check(filename);
        newFile = !check.good();
    }
    std::ofstream f(filename, std::ios::app);
    if (!f.good()) {
        cerr << "Failed to open perf CSV file: " << filename << "\n";
        return;
    }
    if (newFile) {
        f << "Timestamp,Nodes,Workers,Avg Total (us),Min (us),Max (us),Median (us),Success %,Dropped %,Wall Time (s)\n";
    }
    f << currentTimestamp() << "," << nodes << "," << workers << "," << avg_us << "," << min_us << "," << max_us << "," << med_us << ","
      << std::fixed << std::setprecision(2) << success_pct << "," << drop_pct << "," << std::fixed << std::setprecision(6) << wall_time_s << "\n";
    f.close();
}
void write_summary_txt(
    int nodes, int workers, long long avg_us, long long min_us, long long max_us, long long med_us,
    double success_pct, double drop_pct, double wall_time_s, const std::string& filename
) {
    std::ofstream fout(filename, std::ios::app);
    if (!fout.good()) return;
    fout << "Performance Summary Report\n";
    fout << "Generated: " << currentTimestamp() << "\n";
    fout << "-----------------------------------------\n";
    fout << "Nodes: " << nodes << "\n";
    fout << "Workers: " << workers << "\n";
    fout << "Average Time Per Node: " << (avg_us/1000.0) << " ms\n";
    fout << "Minimum Time Observed: " << (min_us/1000.0) << " ms\n";
    fout << "Maximum Time Observed: " << (max_us/1000.0) << " ms\n";
    fout << "Median Time Per Node: " << (med_us/1000.0) << " ms\n";
    fout << "Success Percentage: " << std::fixed << std::setprecision(2) << success_pct << " %\n";
    fout << "Dropped Percentage: " << std::fixed << std::setprecision(2) << drop_pct << " %\n";
    fout << "Run Wall Time: " << std::fixed << std::setprecision(6) << wall_time_s << " s\n";
    fout << "-----------------------------------------\n\n";
    fout.close();
}

// ---------- Main ----------
int main(int argc, char** argv) {
    // derive keys
    KEY_TA_NODE = deriveKey("passphrase_ta_node_v1");
    KEY_NODE_MW = deriveKey("passphrase_node_mw_v1");
    KEY_TA_MW   = deriveKey("passphrase_ta_mw_v1");

    Config cfg;
    if (!parse_args(argc, argv, cfg)) {
        print_usage(argv[0]);
        return 1;
    }

    cout << "Simulating " << cfg.nodes << " nodes with " << cfg.workers << " workers...\n";
    cout << "Network delays: TA->Node " << cfg.net_delay_ta_node_min << "-" << cfg.net_delay_ta_node_max << "ms, "
         << "Node->MW " << cfg.net_delay_node_mw_min << "-" << cfg.net_delay_node_mw_max << "ms, "
         << "DB " << cfg.db_delay_min << "-" << cfg.db_delay_max << "ms\n";
    cout << "Tamper %: " << cfg.tamper_percent << ", Drop %: " << cfg.fail_percent << ", Payload: " << cfg.payload_bytes << " bytes\n";

    std::vector<NodeMetrics> results;
    results.reserve(cfg.nodes);
    std::mutex res_mutex;
    std::atomic<int> counter{0};

    auto run_start = std::chrono::high_resolution_clock::now();

    // spawn workers
    int workers = std::min(cfg.workers, cfg.nodes);
    std::vector<std::thread> pool;
    pool.reserve(workers);
    std::random_device rd;
    for (int i=0;i<workers;++i) {
        std::mt19937 rng(rd() ^ (i * 7919));
        pool.emplace_back(worker_func, std::ref(counter), std::ref(cfg), std::ref(results), std::ref(res_mutex), std::ref(rng));
    }
    for (auto &t : pool) if (t.joinable()) t.join();

    auto run_end = std::chrono::high_resolution_clock::now();
    double run_total_s = std::chrono::duration_cast<std::chrono::duration<double>>(run_end - run_start).count();

    // compute aggregated stats
    std::vector<long long> totals;
    int success_cnt = 0, drop_cnt = 0;
    for (const auto &m : results) {
        if (m.dropped) ++drop_cnt;
        else totals.push_back(m.total_us);
        if (m.success) ++success_cnt;
    }

    long long avg_total = totals.empty() ? 0 : std::accumulate(totals.begin(), totals.end(), 0LL) / (long long)totals.size();
    long long min_total = totals.empty() ? 0 : *std::min_element(totals.begin(), totals.end());
    long long max_total = totals.empty() ? 0 : *std::max_element(totals.begin(), totals.end());
    long long med_total = median_of_vec(totals);
    double success_pct = results.empty() ? 0.0 : (100.0 * success_cnt / (double)cfg.nodes);
    double drop_pct = results.empty() ? 0.0 : (100.0 * drop_cnt / (double)cfg.nodes);

    // append_perf_csv(cfg.nodes, workers, avg_total, min_total, max_total, med_total, success_pct, drop_pct, run_total_s, cfg.out_file);

    // Write human-readable summary to final.txt
    write_summary_txt(cfg.nodes, workers, avg_total, min_total, max_total, med_total, success_pct, drop_pct, run_total_s, "final.txt");

    cout << "Done. Avg node time: " << (avg_total/1000.0) << " ms, Success: " << success_pct << "%, Dropped: " << drop_pct << "%, Wall time: " << run_total_s << " s\n";
    cout << "Results written to: " << cfg.out_file << " and final.txt" << endl;
    return 0;
}