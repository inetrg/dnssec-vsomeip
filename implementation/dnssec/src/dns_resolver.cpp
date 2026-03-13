//
// Created by mehkir on 21.09.22.
//

#include "../include/dns_resolver.hpp"
#include <arpa/inet.h>
#include <string.h>
#include <vsomeip/internal/logger.hpp>
#include <arpa/nameser.h>

#define EDNSPKSZ 1280 // https://datatracker.ietf.org/doc/html/rfc6891

void cares_callback (void* _data, int _status, int _timeouts, unsigned char* _abuf, int _alen) {
    bool retry = false;
    dns_request* query = reinterpret_cast<dns_request*>(_data);

    switch (_status)
    {
    case ARES_SUCCESS:
        VSOMEIP_DEBUG << __func__ << " Query for " << query->name_ << " succeeded";
        break;
    case ARES_ECONNREFUSED:
        VSOMEIP_DEBUG << __func__ << " Connection refused for query: " << query->name_;
        retry = true;
        break;
    case ARES_ENODATA:
        VSOMEIP_DEBUG << __func__ << "Query for " << query->name_ << " returned no data";
        break;
    case ARES_EFORMERR:
        VSOMEIP_DEBUG << __func__ << "Query for " << query->name_ << " could not be completed due to a format error";
        break;
    case ARES_ESERVFAIL:
        VSOMEIP_DEBUG << __func__ << "Query for " << query->name_ << " could not be completed due to a server failure";
        break;
    case ARES_ENOTFOUND:
        VSOMEIP_DEBUG << __func__ << "Query for " << query->name_ << " could not be completed because the name was not found";
        break;
    case ARES_ENOTIMP:
        VSOMEIP_DEBUG << __func__ << "Query for " << query->name_ << " could not be completed because the query type is not implemented";
        break;
    case ARES_EREFUSED:
        VSOMEIP_DEBUG << __func__ << "Query for " << query->name_ << " could not be completed because the server refused the query";
        break;
    case ARES_ETIMEOUT:
        VSOMEIP_DEBUG << __func__ << "Query for " << query->name_ << " could not be completed because as it timed out";
        break;
    case ARES_ENOMEM:
        VSOMEIP_DEBUG << __func__ << "Query for " << query->name_ << " could not be completed because of memory allocation failure";
        break;
    case ARES_EDESTRUCTION:
        VSOMEIP_DEBUG << __func__ << "Query for " << query->name_ << " could not be completed because the channel was destroyed";
        break;    
    default:
        VSOMEIP_DEBUG << __func__ << "Query for " << query->name_ << " could not be completed due to an unknown error";
        break;
    }

    if (retry) {
        query->resolver_->resolve(query->name_, query->dnsclass_, query->type_, query->callback_, query->arg_);
    }
    else if (_abuf == nullptr || _alen <= 0) {
        VSOMEIP_DEBUG << __func__ << " No data received for query: " << query->name_;
        query->callback_(query->arg_, _status, _timeouts, nullptr, 0);
        free(const_cast<char *>(query->name_));
        delete query;
    }
    else {
        query->resolver_->async_callback(query, _status, _timeouts, _abuf, _alen);
        // query->callback_(query->arg_, _status, _timeouts, _abuf, _alen);
        // free(const_cast<char *>(query->name_));
        // delete query;
    }
}

void dns_resolver::async_callback(dns_request* _query, int _status, int _timeouts,
                unsigned char* _abuf, int _alen) {
    // copy data to an application buffer
    std::string rq_type = (_query->type_ == T_TLSA) ? "TLSA" : ((_query->type_ == 64) ? "SVCB" : "OTHER");

    VSOMEIP_DEBUG << __func__ << " Received data for " << rq_type << " query: " << _query->name_;
    unsigned char* _abuf_copy = new unsigned char[_alen];
    memcpy(_abuf_copy, _abuf, _alen);
    // launch callback in a new thread and detach it
    std::thread([_query, _status, _timeouts, _abuf_copy, _alen]() {
        std::lock_guard<std::mutex> lock(_query->resolver_->callback_mutex_);
        _query->callback_(_query->arg_, _status, _timeouts, _abuf_copy, _alen);
        delete[] _abuf_copy; // free the buffer after callback is done
        free(const_cast<char *>(_query->name_));
        delete _query;
    }).detach();
}

void dns_resolver::resolve(const char* _name, int _dnsclass, int _type, resolver_callback _callback, void* _arg) {
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
        VSOMEIP_DEBUG << __func__ << " Request added to queue, new size: " << dns_requests_.size();
    }
    if (!initialized_) {
        VSOMEIP_DEBUG << __func__ << " dns_resolver is not initialized, wait for init before sending... ";
        initialize();
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
    std::unique_lock<std::mutex> lock(initialize_mutex_, std::defer_lock);
    if (!lock.try_lock()) {
        VSOMEIP_DEBUG << __func__ << " Initialization is already in progress by another thread, skipping initialization here...";
        return ARES_SUCCESS;
    }
    if (!initialized_) {
        ares_library_init(ARES_LIB_INIT_ALL);
        VSOMEIP_DEBUG << __func__ << " Ares library initialized";
        if (!ares_threadsafety()) {
            VSOMEIP_ERROR << __func__ << " Ares is not thread safe";
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
            VSOMEIP_DEBUG << __func__ << " Initializing with options failed with error code: " << ret;
            return 1;
        }
        ares_destroy_options(&options);
        if (change_dns_server(address_) != ARES_SUCCESS) {
            VSOMEIP_DEBUG << __func__ << " Setting servers failed";
            return 1;
        }
        state_ = STARTED;
        initialized_ = true;
        process_thread_ = std::thread(&dns_resolver::process, this);
        VSOMEIP_DEBUG << __func__ << " DNS resolver successfully initialized";
    } else {
        VSOMEIP_DEBUG << __func__ << " DNS resolver is already initialized";
    }
    return ARES_SUCCESS;
}

void dns_resolver::process() {
    static int lookups = 0;
    while (state_ != STOPPED) {
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
                VSOMEIP_DEBUG << __func__ << process_id_ << " Request popped from queue, new size: " << dns_requests_.size();
            }
            lookups++;
            ares_search(channel_, dns_request->name_, dns_request->dnsclass_, dns_request->type_, cares_callback, dns_request);
            VSOMEIP_DEBUG << __func__ << process_id_ << " processed request " << lookups;
        }
    }
    VSOMEIP_DEBUG << __func__ << " DNS process thread terminated";
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
        state_ = STOPPED;
        ares_cancel(channel_);
        condition_variable_.notify_one();
        ares_cancel(channel_);
        process_thread_.join();
        ares_destroy(channel_);
        ares_library_cleanup();
        VSOMEIP_DEBUG << __func__ << process_id_ << " Cleanup finished";
        initialized_ = false;
    }
}
