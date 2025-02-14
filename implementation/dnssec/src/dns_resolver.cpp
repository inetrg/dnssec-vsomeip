//
// Created by mehkir on 21.09.22.
//

#include "../include/dns_resolver.hpp"
#include "../include/logger.hpp"
#include <arpa/inet.h>
#include <string.h>
#include <vsomeip/internal/logger.hpp>

#define EDNSPKSZ 1280 // https://datatracker.ietf.org/doc/html/rfc6891

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
        VSOMEIP_DEBUG << __func__ << " Connection refused for query: " << query->name_ << std::endl;
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

void dns_resolver::resolve(const char* _name, int _dnsclass, int _type, resolver_callback _callback, void* _arg) {
    if (!initialized_) {
        std::cout << "dns_resolver is not initialized, retrying initialization... " << std::endl;
        initialize();
    }
        // throw std::runtime_error("dns_resolver is not initialized, call initialize() first!");
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

int dns_resolver::change_dns_server(in_addr_t _address) {
    address_ = _address;
    ares_addr_node servers;
    servers.next = nullptr;
    servers.family = AF_INET;
    servers.addr.addr4.s_addr = htonl(_address);
    // return ares_set_servers(_channel, &servers);
    return ares_set_servers_csv(channel_, inet_ntoa(servers.addr.addr4));
}

int dns_resolver::initialize() {
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
        // struct in_addr* server = new in_addr();
        // server->s_addr = htonl(address_);
        // options.servers = server;
        // options.nservers = 1;
        // optmask |= ARES_OPT_SERVERS;
        int ret = ares_init_options(&channel_, &options, optmask);
        if (ret != ARES_SUCCESS) {
            std::cout << "Initializing with options failed with error code: " << ret << std::endl;
            VSOMEIP_DEBUG << __func__ << " Initializing with options failed with error code: " << ret << std::endl;
            return 1;
        }
        ares_destroy_options(&options);
        if (change_dns_server(address_) != ARES_SUCCESS) {
            std::cout << "Setting servers failed" << std::endl;
            VSOMEIP_DEBUG << __func__ << " Setting servers failed" << std::endl;
            return 1;
        }
        state_ = STARTED;
        initialized_ = true;
        process_thread_ = std::thread(&dns_resolver::process, this);
        LOG_DEBUG("Process Thread is initialized")
        VSOMEIP_DEBUG << __func__ << " DNS resolver successfully initialized" << std::endl;
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

dns_resolver::dns_resolver(in_addr_t _address, std::string _process_id) {
    address_ = _address;
    process_id_ = _process_id;
    initialize();
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
        ares_cancel(channel_);
        condition_variable_.notify_one();
        ares_cancel(channel_);
        process_thread_.join();
        ares_destroy(channel_);
        ares_library_cleanup();
        LOG_DEBUG("Cleanup finished")
        std::cout << "Cleanup finished" << std::endl;
    }
}
