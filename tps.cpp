// Three-Party Medical IoT Authentication Simulation (improved protocol)
// C++17 + OpenSSL 3.x (libcrypto)
// Build: g++ -std=c++17 -O2 -pthread tps.cpp -lcrypto -o tps
// This project is a protocol simulation. The default SecureElement backend is software-emulated.

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using Clock = std::chrono::steady_clock;
using SysClock = std::chrono::system_clock;
using Bytes = std::vector<unsigned char>;
using std::string;
using std::cout;
using std::cerr;
using std::endl;

namespace crypto {
Bytes randomBytes(size_t n) {
    Bytes out(n);
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) throw std::runtime_error("RAND_bytes failed");
    return out;
}
string hex(const Bytes& in) {
    static const char* d = "0123456789abcdef";
    string out; out.reserve(in.size() * 2);
    for (unsigned char c : in) { out.push_back(d[c >> 4]); out.push_back(d[c & 15]); }
    return out;
}
Bytes unhex(const string& s) {
    if (s.size() % 2) throw std::runtime_error("Invalid hex string");
    auto val=[](char c)->int { if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; };
    Bytes out; out.reserve(s.size()/2);
    for(size_t i=0;i<s.size();i+=2) { int a=val(s[i]), b=val(s[i+1]); if(a<0||b<0) throw std::runtime_error("Invalid hex string"); out.push_back(static_cast<unsigned char>((a<<4)|b)); }
    return out;
}
Bytes hmac256(const Bytes& key, const string& msg) {
    Bytes out(EVP_MAX_MD_SIZE); unsigned int len=0;
    if(!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), out.data(), &len)) throw std::runtime_error("HMAC failed");
    out.resize(len); return out;
}
Bytes sha256(const Bytes& in) {
    Bytes out(32); unsigned int n=0;
    if(EVP_Digest(in.data(), in.size(), out.data(), &n, EVP_sha256(), nullptr)!=1) throw std::runtime_error("SHA-256 failed");
    out.resize(n); return out;
}
Bytes hkdfLike(const Bytes& master, const string& info) {
    // HKDF-Extract/Expand with a fixed, domain-separated salt for this simulation.
    Bytes salt(32, 0x5a);
    Bytes prk=hmac256(salt, string(reinterpret_cast<const char*>(master.data()), master.size()));
    Bytes t=hmac256(prk, info + string(1, '\x01'));
    return t; // 32-byte AES-256 key
}
struct GcmBox { Bytes nonce, ciphertext, tag; };
GcmBox encryptGcm(const Bytes& key, const string& plaintext, const string& aad) {
    GcmBox box; box.nonce=randomBytes(12); box.ciphertext.resize(plaintext.size()+16); box.tag.resize(16);
    EVP_CIPHER_CTX* raw=EVP_CIPHER_CTX_new(); if(!raw) throw std::runtime_error("EVP context allocation failed");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw, EVP_CIPHER_CTX_free);
    int len=0, total=0;
    if(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr)!=1 ||
       EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(box.nonce.size()), nullptr)!=1 ||
       EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), box.nonce.data())!=1) throw std::runtime_error("GCM init failed");
    if(!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()), static_cast<int>(aad.size()))!=1) throw std::runtime_error("GCM AAD failed");
    if(!plaintext.empty() && EVP_EncryptUpdate(ctx.get(), box.ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size()))!=1) throw std::runtime_error("GCM encrypt failed");
    total=len;
    if(EVP_EncryptFinal_ex(ctx.get(), box.ciphertext.data()+total, &len)!=1) throw std::runtime_error("GCM final failed");
    total+=len; box.ciphertext.resize(total);
    if(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, box.tag.data())!=1) throw std::runtime_error("GCM tag failed");
    return box;
}
string decryptGcm(const Bytes& key, const GcmBox& box, const string& aad) {
    Bytes plain(box.ciphertext.size()+16); EVP_CIPHER_CTX* raw=EVP_CIPHER_CTX_new(); if(!raw) throw std::runtime_error("EVP context allocation failed");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw, EVP_CIPHER_CTX_free);
    int len=0,total=0;
    if(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr)!=1 ||
       EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(box.nonce.size()), nullptr)!=1 ||
       EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), box.nonce.data())!=1) throw std::runtime_error("GCM init failed");
    if(!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()), static_cast<int>(aad.size()))!=1) throw std::runtime_error("GCM AAD failed");
    if(!box.ciphertext.empty() && EVP_DecryptUpdate(ctx.get(), plain.data(), &len, box.ciphertext.data(), static_cast<int>(box.ciphertext.size()))!=1) throw std::runtime_error("GCM decrypt failed");
    total=len;
    Bytes tag=box.tag;
    if(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data())!=1) throw std::runtime_error("GCM set tag failed");
    if(EVP_DecryptFinal_ex(ctx.get(), plain.data()+total, &len)!=1) throw std::runtime_error("Authentication tag verification failed");
    total+=len; plain.resize(total); return string(plain.begin(), plain.end());
}
}

static int64_t unixSeconds() { return std::chrono::duration_cast<std::chrono::seconds>(SysClock::now().time_since_epoch()).count(); }
static string timestamp() { std::time_t t=std::time(nullptr); std::tm tm{}; localtime_r(&t,&tm); std::ostringstream o; o<<std::put_time(&tm,"%Y-%m-%d %H:%M:%S"); return o.str(); }
static string joinFields(const std::vector<string>& v) { string s; for(size_t i=0;i<v.size();++i){if(i)s+='|';s+=v[i];} return s; }
static std::vector<string> split(const string& s, char delim='|') { std::vector<string> v; std::stringstream ss(s); string x; while(std::getline(ss,x,delim))v.push_back(x); return v; }

struct Config {
    int nodes=100, workers=4, payloadBytes=500, jitterMs=30, messagesPerNode=1;
    int netTaNodeMin=2, netTaNodeMax=8, netNodeMwMin=2, netNodeMwMax=8, dbMin=2, dbMax=8;
    double tamperPct=0, failPct=0, replayPct=0, hardwareFailPct=0, expiredPct=0;
    int maxClockSkewSec=5, tokenTtlSec=60, replayTtlSec=120, rotationSeconds=900, rotateAfterMessages=10000, previousKeyGraceSec=30;
    string csv="results.csv", summary="tps.txt";
};
bool parseArgs(int argc,char**argv,Config&c){
    auto need=[&](int i,int n){return i+n<argc;};
    for(int i=1;i<argc;++i){string a=argv[i];
        if(a=="--help"||a=="-h")return false;
        else if(a=="--nodes"&&need(i,1))c.nodes=std::stoi(argv[++i]);
        else if(a=="--workers"&&need(i,1))c.workers=std::stoi(argv[++i]);
        else if(a=="--payload-bytes"&&need(i,1))c.payloadBytes=std::stoi(argv[++i]);
        else if(a=="--messages-per-node"&&need(i,1))c.messagesPerNode=std::stoi(argv[++i]);
        else if(a=="--node-jitter"&&need(i,1))c.jitterMs=std::stoi(argv[++i]);
        else if(a=="--net-ta-node"&&need(i,2)){c.netTaNodeMin=std::stoi(argv[++i]);c.netTaNodeMax=std::stoi(argv[++i]);}
        else if(a=="--net-node-mw"&&need(i,2)){c.netNodeMwMin=std::stoi(argv[++i]);c.netNodeMwMax=std::stoi(argv[++i]);}
        else if(a=="--db-delay"&&need(i,2)){c.dbMin=std::stoi(argv[++i]);c.dbMax=std::stoi(argv[++i]);}
        else if(a=="--tamper-percent"&&need(i,1))c.tamperPct=std::stod(argv[++i]);
        else if(a=="--fail-percent"&&need(i,1))c.failPct=std::stod(argv[++i]);
        else if(a=="--replay-percent"&&need(i,1))c.replayPct=std::stod(argv[++i]);
        else if(a=="--hardware-fail-percent"&&need(i,1))c.hardwareFailPct=std::stod(argv[++i]);
        else if(a=="--expired-percent"&&need(i,1))c.expiredPct=std::stod(argv[++i]);
        else if(a=="--max-clock-skew"&&need(i,1))c.maxClockSkewSec=std::stoi(argv[++i]);
        else if(a=="--token-ttl"&&need(i,1))c.tokenTtlSec=std::stoi(argv[++i]);
        else if(a=="--replay-ttl"&&need(i,1))c.replayTtlSec=std::stoi(argv[++i]);
        else if(a=="--rotation-seconds"&&need(i,1))c.rotationSeconds=std::stoi(argv[++i]);
        else if(a=="--rotate-after-messages"&&need(i,1))c.rotateAfterMessages=std::stoi(argv[++i]);
        else if(a=="--previous-key-grace"&&need(i,1))c.previousKeyGraceSec=std::stoi(argv[++i]);
        else if(a=="--out"&&need(i,1))c.csv=argv[++i];
        else if(a=="--summary"&&need(i,1))c.summary=argv[++i];
        else {cerr<<"Unknown or incomplete argument: "<<a<<"\n";return false;}
    }
    if(c.nodes<1||c.workers<1||c.payloadBytes<0||c.jitterMs<0||c.messagesPerNode<1||c.maxClockSkewSec<0||c.tokenTtlSec<1||c.replayTtlSec<1||c.rotationSeconds<1||c.rotateAfterMessages<1||c.previousKeyGraceSec<0) return false;
    auto range=[](int a,int b){return a>=0&&b>=a;}; if(!range(c.netTaNodeMin,c.netTaNodeMax)||!range(c.netNodeMwMin,c.netNodeMwMax)||!range(c.dbMin,c.dbMax))return false;
    for(double p:{c.tamperPct,c.failPct,c.replayPct,c.hardwareFailPct,c.expiredPct})if(p<0||p>100)return false;
    return true;
}
void usage(const char*p){cout<<"Usage: "<<p<<" [--nodes N] [--workers N] [--tamper-percent P] [--replay-percent P]\n"
    <<"  [--hardware-fail-percent P] [--expired-percent P] [--fail-percent P] [--payload-bytes N] [--messages-per-node N]\n"
    <<"  [--max-clock-skew SEC] [--token-ttl SEC] [--replay-ttl SEC] [--rotation-seconds SEC]\n"
    <<"  [--rotate-after-messages N] [--previous-key-grace SEC] [--net-ta-node MIN MAX]\n"
    <<"  [--net-node-mw MIN MAX] [--db-delay MIN MAX] [--node-jitter MS] [--out CSV] [--summary TXT]\n";}

// Software-emulated secure element: private material is encapsulated behind this interface.
// A physical implementation would replace this class with TPM2/SE driver calls.
class SecureElement {
    Bytes deviceSecret_;
public:
    explicit SecureElement(Bytes secret):deviceSecret_(std::move(secret)){}
    Bytes provePossession(const string& challenge) const { return crypto::hmac256(deviceSecret_,challenge); }
    Bytes deriveSessionKey(const string&id,uint64_t version) const { return crypto::hkdfLike(deviceSecret_,"medical-iot/session/"+id+"/"+std::to_string(version)); }
};
struct DeviceRecord { Bytes secret; };
class TrustedAuthority {
    Bytes tokenSigningKey_;
    mutable std::mutex mutex_;
    std::unordered_map<string,DeviceRecord> registry_;
public:
    TrustedAuthority():tokenSigningKey_(crypto::randomBytes(32)){}
    string createChallenge() const { return crypto::hex(crypto::randomBytes(32)); }
    Bytes enroll(const string&id) { Bytes secret=crypto::randomBytes(32); std::lock_guard<std::mutex>l(mutex_); registry_[id]={secret}; return secret; }
    bool verifyProof(const string&id,const string&challenge,const Bytes&proof){std::lock_guard<std::mutex>l(mutex_);auto it=registry_.find(id);if(it==registry_.end())return false;Bytes expected=crypto::hmac256(it->second.secret,challenge);return expected.size()==proof.size()&&CRYPTO_memcmp(expected.data(),proof.data(),expected.size())==0;}
    Bytes sessionKey(const string&id,uint64_t version)const{std::lock_guard<std::mutex>l(mutex_);auto it=registry_.find(id);if(it==registry_.end())throw std::runtime_error("Unknown device");return crypto::hkdfLike(it->second.secret,"medical-iot/session/"+id+"/"+std::to_string(version));}
    string issueToken(const string&id,uint64_t seq,int64_t issued,int64_t expires,uint64_t version,const string&nonce){
        string body=joinFields({id,std::to_string(seq),std::to_string(issued),std::to_string(expires),std::to_string(version),nonce});
        Bytes sig=crypto::hmac256(tokenSigningKey_,body);return body+"|"+crypto::hex(sig);
    }
    bool verifyToken(const string&token,std::vector<string>&fields)const{
        fields=split(token);if(fields.size()!=7)return false;string body=token.substr(0,token.rfind('|'));Bytes sig;
        try{sig=crypto::unhex(fields[6]);}catch(...){return false;}Bytes expected=crypto::hmac256(tokenSigningKey_,body);
        return sig.size()==expected.size()&&CRYPTO_memcmp(sig.data(),expected.data(),sig.size())==0;
    }
};

class ReplayGuard {
    struct State{uint64_t highestSeq=0;std::unordered_map<string,int64_t> nonces;};
    std::mutex mutex_;std::unordered_map<string,State> state_;int64_t ttl_;
public:
    explicit ReplayGuard(int64_t ttl):ttl_(ttl){}
    bool accept(const string&id,uint64_t seq,const string&nonce,int64_t now){std::lock_guard<std::mutex>l(mutex_);auto&s=state_[id];
        for(auto it=s.nonces.begin();it!=s.nonces.end();)if(it->second<now-ttl_)it=s.nonces.erase(it);else ++it;
        if(seq<=s.highestSeq||s.nonces.count(nonce)) return false;
        s.highestSeq=seq; s.nonces[nonce]=now; return true; }
};
struct Request { string id,token;uint64_t seq=0,version=0;int64_t timestamp=0;string nonce;crypto::GcmBox box; };
struct Metrics {int index=0;long long micros=0;bool success=false,dropped=false;string outcome="rejected";};
static uint64_t makeKeyVersion(int64_t issued,uint64_t seq,const Config&cfg){
    // High-order component rotates on wall-clock intervals; low-order component rotates every N messages/device.
    return static_cast<uint64_t>(issued/cfg.rotationSeconds)*1000000000ULL + ((seq-1)/static_cast<uint64_t>(cfg.rotateAfterMessages));
}

class Middleware {
    TrustedAuthority&ta_;ReplayGuard replay_;const Config&cfg_;
public:
    Middleware(TrustedAuthority&t,const Config&c):ta_(t),replay_(c.replayTtlSec),cfg_(c){}
    bool process(const Request&r,string&reason){
        std::vector<string> f;if(!ta_.verifyToken(r.token,f)){reason="invalid_token";return false;}
        if(f[0]!=r.id){reason="identity_mismatch";return false;}
        uint64_t seq=0,ver=0;int64_t issued=0,expires=0;try{seq=std::stoull(f[1]);issued=std::stoll(f[2]);expires=std::stoll(f[3]);ver=std::stoull(f[4]);}catch(...){reason="malformed_token";return false;}
        int64_t now=unixSeconds();if(issued>now+cfg_.maxClockSkewSec||now-issued>cfg_.maxClockSkewSec){reason="stale_or_future_timestamp";return false;}
        if(now>expires){reason="expired_token";return false;}if(seq!=r.seq||ver!=r.version||f[5]!=r.nonce){reason="request_token_mismatch";return false;}
        // Strictly reject old/future request timestamps independently of token expiry.
        if(std::llabs(now-r.timestamp)>cfg_.maxClockSkewSec){reason="request_timestamp_out_of_window";return false;}
        uint64_t expectedVersion=makeKeyVersion(issued,seq,cfg_);
        if(r.version!=expectedVersion){reason="key_version_mismatch";return false;}
        int64_t issuedBucket=issued/cfg_.rotationSeconds, currentBucket=now/cfg_.rotationSeconds;
        if(currentBucket>issuedBucket && now%cfg_.rotationSeconds>cfg_.previousKeyGraceSec){reason="key_rotation_grace_expired";return false;}
        if(currentBucket-issuedBucket>1){reason="key_version_expired";return false;}
        try{string aad=r.id+"|"+std::to_string(r.seq)+"|"+std::to_string(r.timestamp)+"|"+std::to_string(r.version);
            string plaintext=crypto::decryptGcm(ta_.sessionKey(r.id,r.version),r.box,aad);if(plaintext.empty()&&cfg_.payloadBytes>0){reason="empty_payload";return false;}}
        catch(...){reason="integrity_check_failed";return false;}
        // Commit replay state only after token, time, key-version and AEAD checks succeed.
        if(!replay_.accept(r.id,r.seq,r.nonce,now)){reason="replay_detected";return false;}
        reason="accepted";return true;
    }
};

static double randomPct(std::mt19937&r){return std::uniform_real_distribution<double>(0,100)(r);}
void worker(std::atomic<int>&next,const Config&cfg,std::vector<Metrics>&out,std::mutex&outMutex,TrustedAuthority&ta,Middleware&mw,std::mt19937 rng){
    std::uniform_int_distribution<int> jitter(0,cfg.jitterMs),d1(cfg.netTaNodeMin,cfg.netTaNodeMax),d2(cfg.netNodeMwMin,cfg.netNodeMwMax),db(cfg.dbMin,cfg.dbMax);
    while(true){int idx=next.fetch_add(1);if(idx>=cfg.nodes)break;Metrics m;m.index=idx;auto start=Clock::now();
        try{
            std::this_thread::sleep_for(std::chrono::milliseconds(jitter(rng)));
            std::this_thread::sleep_for(std::chrono::milliseconds(d1(rng)));
            if(randomPct(rng)<cfg.failPct){m.dropped=true;m.outcome="network_drop";}
            else{
                string id="medical-node-"+std::to_string(idx);Bytes secret=ta.enroll(id);SecureElement se(secret);
                string challenge=ta.createChallenge();Bytes proof=se.provePossession(challenge);
                if(randomPct(rng)<cfg.hardwareFailPct)proof=crypto::randomBytes(32);
                if(!ta.verifyProof(id,challenge,proof)){m.outcome="device_authentication_failed";}
                else{
                    m.success=true; m.outcome="accepted";
                    for(int message=0;message<cfg.messagesPerNode;++message){
                        int64_t now=unixSeconds();uint64_t seq=static_cast<uint64_t>(message)+1;
                        uint64_t version=makeKeyVersion(now,seq,cfg);
                        string nonce=crypto::hex(crypto::randomBytes(16));int64_t expires=now+cfg.tokenTtlSec;
                        if(randomPct(rng)<cfg.expiredPct)expires=now-1;
                        string token=ta.issueToken(id,seq,now,expires,version,nonce);
                        string payload(static_cast<size_t>(cfg.payloadBytes),static_cast<char>('A'+idx%26));
                        string aad=id+"|"+std::to_string(seq)+"|"+std::to_string(now)+"|"+std::to_string(version);
                        Request req;req.id=id;req.seq=seq;req.version=version;req.timestamp=now;req.nonce=nonce;req.token=token;
                        req.box=crypto::encryptGcm(se.deriveSessionKey(id,version),payload,aad);
                        // Tamper after encryption so the receiver must detect a failed GCM tag.
                        if(randomPct(rng)<cfg.tamperPct && !req.box.ciphertext.empty()) req.box.ciphertext[0] ^= 0x01;
                        std::this_thread::sleep_for(std::chrono::milliseconds(d2(rng)));
                        string reason;bool accepted=mw.process(req,reason);
                        if(randomPct(rng)<cfg.replayPct && accepted){string replayReason;bool replayAccepted=mw.process(req,replayReason);if(replayAccepted){m.success=false;m.outcome="replay_accepted";}else if(m.outcome=="accepted")m.outcome="replay_rejected";}
                        if(!accepted){m.success=false;m.outcome=reason;}
                        std::this_thread::sleep_for(std::chrono::milliseconds(db(rng)));
                        if(!m.success)break;
                    }
                }
            }
        }catch(const std::exception&e){m.success=false;m.outcome=string("internal_error:")+e.what();}
        m.micros=std::chrono::duration_cast<std::chrono::microseconds>(Clock::now()-start).count();
        std::lock_guard<std::mutex>l(outMutex);out.push_back(std::move(m));
    }
}
long long median(std::vector<long long>v){if(v.empty())return 0;std::sort(v.begin(),v.end());size_t n=v.size();return n%2?v[n/2]:(v[n/2-1]+v[n/2])/2;}
int main(int argc,char**argv){Config cfg;if(!parseArgs(argc,argv,cfg)){usage(argv[0]);for(int i=1;i<argc;++i)if(string(argv[i])=="--help"||string(argv[i])=="-h")return 0;return 1;}
    cout<<"Three-Party Medical IoT Authentication Simulation (improved protocol)\n"
        <<"Nodes="<<cfg.nodes<<" Workers="<<cfg.workers<<" Messages/node="<<cfg.messagesPerNode<<" Payload="<<cfg.payloadBytes<<" bytes\n"
        <<"Security: AES-256-GCM, HMAC-SHA256 tokens/device proof, HKDF-style session derivation\n"
        <<"Clock skew="<<cfg.maxClockSkewSec<<"s Token TTL="<<cfg.tokenTtlSec<<"s Replay TTL="<<cfg.replayTtlSec<<"s Rotation="<<cfg.rotationSeconds<<"s\n"
        <<"Secure Element backend: SOFTWARE EMULATION (not physical hardware)\n";
    TrustedAuthority ta;Middleware mw(ta,cfg);std::atomic<int>next{0};std::mutex outMutex;std::vector<Metrics>results;results.reserve(cfg.nodes);
    auto runStart=Clock::now();int nworkers=std::min(cfg.workers,cfg.nodes);std::vector<std::thread>pool;std::random_device rd;
    for(int i=0;i<nworkers;++i)pool.emplace_back(worker,std::ref(next),std::cref(cfg),std::ref(results),std::ref(outMutex),std::ref(ta),std::ref(mw),std::mt19937(rd()^(i*7919)));
    for(auto&t:pool) t.join();
    double wall=std::chrono::duration<double>(Clock::now()-runStart).count();
    std::vector<long long>times;int accepted=0,dropped=0;std::map<string,int>outcomes;
    for(auto&m:results){if(!m.dropped)times.push_back(m.micros);else ++dropped;if(m.success)++accepted;++outcomes[m.outcome];}
    long long avg=times.empty()?0:std::accumulate(times.begin(),times.end(),0LL)/times.size(),mn=times.empty()?0:*std::min_element(times.begin(),times.end()),mx=times.empty()?0:*std::max_element(times.begin(),times.end()),med=median(times);
    double successPct=100.0*accepted/cfg.nodes,dropPct=100.0*dropped/cfg.nodes;
    std::ofstream s(cfg.summary,std::ios::app);s<<"\nImproved Three-Party Protocol Summary\nGenerated: "<<timestamp()<<"\nNodes: "<<cfg.nodes<<"\nWorkers: "<<nworkers<<"\nAccepted requests: "<<accepted<<"\nSuccess percentage: "<<std::fixed<<std::setprecision(2)<<successPct<<"%\nNetwork drops: "<<dropped<<" ("<<dropPct<<"%)\nAverage latency: "<<avg/1000.0<<" ms\nMedian latency: "<<med/1000.0<<" ms\nMin/Max latency: "<<mn/1000.0<<" / "<<mx/1000.0<<" ms\nWall time: "<<wall<<" s\nOutcome counts:\n";for(auto&x:outcomes)s<<"  "<<x.first<<": "<<x.second<<"\n";s<<"----------------------------------------\n";
    bool fresh=!std::ifstream(cfg.csv).good();std::ofstream csv(cfg.csv,std::ios::app);if(fresh)csv<<"timestamp,nodes,workers,accepted,success_pct,dropped,drop_pct,avg_us,median_us,min_us,max_us,wall_seconds\n";
    csv<<'"'<<timestamp()<<"\","<<cfg.nodes<<','<<nworkers<<','<<accepted<<','<<successPct<<','<<dropped<<','<<dropPct<<','<<avg<<','<<med<<','<<mn<<','<<mx<<','<<wall<<"\n";
    cout<<"\nRun complete. Accepted="<<accepted<<" ("<<successPct<<"%), dropped="<<dropped<<" ("<<dropPct<<"%).\n"
        <<"Average latency="<<avg/1000.0<<" ms; median="<<med/1000.0<<" ms; wall="<<wall<<" s\n"
        <<"Detailed outcomes:\n";for(auto&x:outcomes)cout<<"  "<<x.first<<": "<<x.second<<"\n";
    cout<<"Summary: "<<cfg.summary<<"\nCSV: "<<cfg.csv<<"\n";return 0;
}
