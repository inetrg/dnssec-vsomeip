//
// Created by mehkir on 21.09.22.
//

#ifndef VSOMEIP_DNS_RESOLVER_HPP
#define VSOMEIP_DNS_RESOLVER_HPP

#define DEFAULT_SERVER 0xAC110002 // 0xAC=172 0x11=17 0x00=0 0x02=2 -> 172.17.0.2

#include <mutex>
#include <thread>
#include <ares.h>
#include <stdexcept>
#include <iostream>
#include <condition_variable>
#include <deque>
#include <functional>

class dns_resolver;
typedef std::function<void(void*, int, int, unsigned char*, int)> resolver_callback;

struct dns_request {
    const char* name_ = "";
    int dnsclass_ = 0;
    int type_ = 0;
    resolver_callback callback_;
    void* arg_ = nullptr;
    dns_resolver* resolver_ = nullptr;
};

class dns_resolver {

public:
    dns_resolver(in_addr_t _address=DEFAULT_SERVER, std::string _process_id="");
    ~dns_resolver();
    void cleanup();
    void resolve(const char* _name, int _dnsclass, int _type, resolver_callback _callback, void* _arg);
    int change_dns_server(in_addr_t _address);
    void async_callback(dns_request* _query, int _status, int _timeouts,
                        unsigned char* _abuf, int _alen);
protected:
private:
    int initialize();
    const int STARTED = 0;
    const int STOPPED = 1;
    int state_ = STOPPED;
    bool initialized_ = false;
    ares_channel_t* channel_;
    std::thread process_thread_;
    std::condition_variable condition_variable_;
    std::mutex mutex_;
    std::mutex initialize_mutex_;
    std::mutex callback_mutex_;
    void process();
    in_addr_t address_;
    std::deque<dns_request*> dns_requests_;
    std::string process_id_;
};

#endif //VSOMEIP_DNS_RESOLVER_HPP
