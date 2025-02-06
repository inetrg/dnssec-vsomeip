//
// Created by mehkir on 21.09.22.
//

#include "../include/dns_resolver.hpp"
#include "../include/logger.hpp"
#include <arpa/inet.h>
#include <string.h>

#define EDNSPKSZ 1280 // https://datatracker.ietf.org/doc/html/rfc6891
#define CONN_REFUSE_WAIT_US 1000000
std::mutex dns_resolver::mutex_;
dns_resolver* dns_resolver::instance_;

void cares_callback (void* _data, int _status, int _timeouts, unsigned char* _abuf, int _alen) {
    bool retry = false;
    dns_request* query = reinterpret_cast<dns_request*>(_data);

    switch (_status)
    {
    case ARES_SUCCESS:
        std::cout << "Query for " << query->name_ << " succeeded" << std::endl;
        break;
    case ARES_ECONNREFUSED:
        std::cout << "Query for " << query->name_ << " could not be completed because the connection was refused" << std::endl;
        query->resolver_->conn_refused();
        retry = true;
        break;
    case ARES_ENODATA:
        std::cout << "Query for " << query->name_ << " returned no data" << std::endl;
        break;
    case ARES_EFORMERR:
        std::cout << "Query for " << query->name_ << " could not be completed due to a format error" << std::endl;
        break;
    case ARES_ESERVFAIL:
        std::cout << "Query for " << query->name_ << " could not be completed due to a server failure" << std::endl;
        break;
    case ARES_ENOTFOUND:
        std::cout << "Query for " << query->name_ << " could not be completed because the name was not found" << std::endl;
        break;
    case ARES_ENOTIMP:
        std::cout << "Query for " << query->name_ << " could not be completed because the query type is not implemented" << std::endl;
        break;
    case ARES_EREFUSED:
        std::cout << "Query for " << query->name_ << " could not be completed because the server refused the query" << std::endl;
        break;
    case ARES_ETIMEOUT:
        std::cout << "Query for " << query->name_ << " could not be completed because as it timed out" << std::endl;
        break;
    case ARES_ENOMEM:
        std::cout << "Query for " << query->name_ << " could not be completed because of memory allocation failure" << std::endl;
        break;
    case ARES_EDESTRUCTION:
        std::cout << "Query for " << query->name_ << " could not be completed because the channel was destroyed" << std::endl;
        break;    
    default:
        std::cout << "Query for " << query->name_ << " could not be completed due to an unknown error" << std::endl;
        break;
    }

    if (retry) {
        query->resolver_->resolve(query->name_, query->dnsclass_, query->type_, query->callback_, query->arg_);
    }
    else {
        query->callback_(query->arg_, _status, _timeouts, _abuf, _alen);
    }
    free(const_cast<char *>(query->name_));
    delete query;
}

dns_resolver* dns_resolver::get_instance() {
    std::lock_guard<std::mutex> lockguard(mutex_);
    if(instance_ == nullptr) {
        instance_ = new dns_resolver();
    }
    return instance_;
}

void dns_resolver::resolve(const char* _name, int _dnsclass, int _type, ares_callback _callback, void* _arg) {
    if (!initialized_)
        throw std::runtime_error("dns_resolver is not initialized, call initialize() first!");
    dns_request* _dns_request = new dns_request();
    char* url = (char*)malloc(strlen(_name)+1);
    strcpy(url, _name);
    _dns_request->name_ = url;
    _dns_request->dnsclass_ = _dnsclass;
    _dns_request->type_ = _type;
    _dns_request->callback_ = _callback;
    _dns_request->arg_ = _arg;
    _dns_request->resolver_ = this;
    {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        dns_requests_.push_back(_dns_request);
        std::cout << process_id_ << " Request added to queue, new size: " << dns_requests_.size() << std::endl;
    }
    condition_variable_.notify_one();
}

void dns_resolver::conn_refused() {
    conn_refuse_wait_us_ = std::chrono::microseconds(CONN_REFUSE_WAIT_US);
}

int dns_resolver::change_dns_server(ares_channel& _channel, in_addr_t _address) {
    ares_addr_node servers;
    servers.next = nullptr;
    servers.family = AF_INET;
    servers.addr.addr4.s_addr = htonl(_address);
    // return ares_set_servers(_channel, &servers);
    return ares_set_servers_csv(_channel, inet_ntoa(servers.addr.addr4));
}

int dns_resolver::initialize(in_addr_t _address, std::string _process_id) {
    std::lock_guard<std::mutex> lock_guard(mutex_);
    if (!initialized_) {
        ares_library_init(ARES_LIB_INIT_ALL);
        std::cout << "Ares library initialized" << std::endl;
        if (!ares_threadsafety()) {
            std::cout << "Ares is not thread safe" << std::endl;
            return 1;
        }

        ares_options options;
        memset(&options, 0, sizeof(options));
        int optmask = 0;
        optmask      |= ARES_OPT_EVENT_THREAD;
        options.evsys = ARES_EVSYS_DEFAULT;
        options.flags |= ARES_FLAG_USEVC;
        options.flags |= ARES_FLAG_STAYOPEN;
        // options.flags |= ARES_FLAG_EDNS;
        optmask |= ARES_OPT_FLAGS;
        // optmask |= ARES_OPT_EDNSPSZ;
        // options.ednspsz = EDNSPKSZ;
        if (ares_init_options(&channel_, &options, optmask) != ARES_SUCCESS) {
            std::cout << "Initializing with options failed" << std::endl;
            return 1;
        }
        ares_destroy_options(&options);
        if (change_dns_server(channel_, _address) != ARES_SUCCESS) {
            std::cout << "Setting servers failed" << std::endl;
            return 1;
        }
        conn_refuse_wait_us_ = std::chrono::microseconds(0);
        process_id_ = _process_id;
        state_ = STARTED;
        process_thread_ = std::thread(&dns_resolver::process, this);
        initialized_ = true;
        LOG_DEBUG("Process Thread is initialized")
    } else {
        LOG_DEBUG("Process Thread is already initialized")
    }
    return ARES_SUCCESS;
}

void dns_resolver::process() {
    static int lookups = 0;
    while (state_ != STOPPED) {
        LOG_DEBUG("Process thread performed unique lock")
        {
            std::unique_lock<std::mutex> unique_lock(mutex_);
            condition_variable_.wait(unique_lock, [this] { return !dns_requests_.empty() || state_ == STOPPED; });
        }
        if (conn_refuse_wait_us_.count() > 0) {
            std::this_thread::sleep_for(conn_refuse_wait_us_);
            conn_refuse_wait_us_ = std::chrono::microseconds(0);
        }
        if (state_ != STOPPED) {
            dns_request* dns_request;
            {
                std::lock_guard<std::mutex> lockguard(mutex_);
                if (dns_requests_.empty()) {
                    continue;
                }
                dns_request = dns_requests_.front();
                dns_requests_.pop_front();
                std::cout << process_id_ << " Request popped from queue, new size: " << dns_requests_.size() << std::endl;
            }
            lookups++;
            ares_search(channel_, dns_request->name_, dns_request->dnsclass_, dns_request->type_, cares_callback, dns_request);
            std::cout << process_id_ << " processed request " << lookups << std::endl;
        } else {
            LOG_DEBUG("Process thread is about to exit")
        }
    }
    LOG_DEBUG("Process thread terminated")
}

dns_resolver::dns_resolver() {
}

dns_resolver::~dns_resolver() {
    cleanup();
    for (auto& dns_request : dns_requests_) {
        free(const_cast<char *>(dns_request->name_));
        delete dns_request;
    }
}

void dns_resolver::cleanup() {
    if (initialized_) {
        LOG_DEBUG("Cleanup begins")
        state_ = STOPPED;
        condition_variable_.notify_one();
        process_thread_.join();
        ares_destroy(channel_);
        ares_library_cleanup();
        LOG_DEBUG("Cleanup finished")
    }
}
