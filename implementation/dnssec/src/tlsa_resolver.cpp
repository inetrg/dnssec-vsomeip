#include "../include/tlsa_resolver.hpp"
#include "../include/parse_tlsa_reply.hpp"
#include <vsomeip/internal/logger.hpp>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <cstring>

namespace vsomeip_v3 {
    tlsa_resolver::tlsa_resolver(std::shared_ptr<dns_resolver> _dns_resolver) : dns_resolver_(_dns_resolver) {
    }

    tlsa_resolver::~tlsa_resolver() {
    }

    void tlsa_resolver::service_tlsa_resolve_callback(void* _data, int _status, int _timeouts,
                unsigned char* _abuf, int _alen) {
        (void)_timeouts;
        service_data_and_cbs* servicedata_and_cbs = reinterpret_cast<service_data_and_cbs*>(_data);
        
        if (_status) {
            VSOMEIP_DEBUG << __func__ << " Bad DNS response" << std::endl;
            std::cout << "Bad DNS response" << std::endl;
            delete servicedata_and_cbs;
            return;
        }

        VSOMEIP_DEBUG << __func__ << " TLSA SERVICE RESPONSE RECEIVE";
        servicedata_and_cbs->record_timestamp_callback_(servicedata_and_cbs->service_, servicedata_and_cbs->its_unicast_.to_uint(), time_metric::TLSA_SERVICE_RESPONSE_RECEIVE_);

        unsigned char* copy = new unsigned char[_alen];
        memcpy(copy, _abuf, _alen);
        tlsa_reply* tlsareply;
        if ((parse_tlsa_reply(copy, _alen, &tlsareply)) != ARES_SUCCESS) {
            VSOMEIP_DEBUG << "Parsing service TLSA reply failed" << std::endl;
            std::cout << "Parsing service TLSA reply failed" << std::endl;
            delete servicedata_and_cbs;
            delete[] copy;
            delete_tlsa_reply(tlsareply);
            return;
        }

        tlsa_reply* tlsa_reply_ptr = tlsareply;
        while (tlsa_reply_ptr != nullptr) {
            servicedata_and_cbs->add_publisher_certificate_callback_(servicedata_and_cbs->ipv4_address_, servicedata_and_cbs->service_, servicedata_and_cbs->instance_, servicedata_and_cbs->convert_der_to_pem_callback_(tlsa_reply_ptr->certificate_association_data_));
            servicedata_and_cbs->validate_subscribe_ack_and_verify_signature_callback_(servicedata_and_cbs->ipv4_address_, servicedata_and_cbs->service_, servicedata_and_cbs->instance_, servicedata_and_cbs->major_);
            tlsa_reply_ptr = tlsa_reply_ptr->tlsa_reply_next_;
        }
        VSOMEIP_DEBUG << "Service TLSA Resolved Service: " << servicedata_and_cbs->service_;
        close_service_request(servicedata_and_cbs->dns_name_);
        delete servicedata_and_cbs;
        delete[] copy;
        delete_tlsa_reply(tlsareply);
    }

    void tlsa_resolver::client_tlsa_resolve_callback(void* _data, int _status, int _timeouts,
                unsigned char* _abuf, int _alen) {
        (void)_timeouts;
        client_data_and_cbs* clientdata_and_cbs = reinterpret_cast<client_data_and_cbs*>(_data);
        VSOMEIP_DEBUG << __func__ << " TLSA CLIENT RESPONSE RECEIVE";
        if (_status) {
            VSOMEIP_DEBUG << __func__ << " Bad DNS response" << std::endl;
            delete clientdata_and_cbs;
            return;
        }

        clientdata_and_cbs->record_timestamp_callback_(clientdata_and_cbs->service_,clientdata_and_cbs->unverified_client_ipv4_address_.to_uint(), time_metric::TLSA_CLIENT_RESPONSE_RECEIVE_);

        unsigned char* copy = new unsigned char[_alen];
        memcpy(copy, _abuf, _alen);
        tlsa_reply* tlsareply;
        if ((parse_tlsa_reply(copy, _alen, &tlsareply)) != ARES_SUCCESS) {
            VSOMEIP_DEBUG << "Parsing client TLSA reply failed" << std::endl;
            delete clientdata_and_cbs;
            delete[] copy;
            delete_tlsa_reply(tlsareply);
            return;
        }

        tlsa_reply* tlsa_reply_ptr = tlsareply;
        while (tlsa_reply_ptr != nullptr) {
            clientdata_and_cbs->add_subscriber_certificate_callback_(clientdata_and_cbs->client_, clientdata_and_cbs->ipv4_address_, clientdata_and_cbs->service_, clientdata_and_cbs->instance_, clientdata_and_cbs->convert_der_to_pem_callback_(tlsa_reply_ptr->certificate_association_data_));
            tlsa_reply_ptr = tlsa_reply_ptr->tlsa_reply_next_;
        }
        VSOMEIP_DEBUG << "Client TLSA Resolved Service: " << clientdata_and_cbs->service_ << " for Client: " << clientdata_and_cbs->client_;
        clientdata_and_cbs->validate_subscribe_and_verify_signature_callback_(clientdata_and_cbs->client_, clientdata_and_cbs->ipv4_address_, clientdata_and_cbs->service_, clientdata_and_cbs->instance_, clientdata_and_cbs->major_, true);
        close_client_request(clientdata_and_cbs->dns_name_);
        delete clientdata_and_cbs;
        delete[] copy;
        delete_tlsa_reply(tlsareply);
    }

    void tlsa_resolver::request_service_tlsa_record(void* _service_data) {
        service_data_and_cbs* servicedata_and_cbs = reinterpret_cast<service_data_and_cbs*>(_service_data);
        std::stringstream request;
        request << ATTRLEAFBRANCH;
        request << "minor0x" << std::hex << std::setw(8) << std::setfill('0') << (int) servicedata_and_cbs->minor_;
        request << ".";
        request << "major0x" << std::hex << std::setw(2) << std::setfill('0') << (int) servicedata_and_cbs->major_;
        request << ".";
        request << "instance0x" << std::hex << std::setw(4) << std::setfill('0') << (int) servicedata_and_cbs->instance_;
        request << ".";
        request << "id0x" << std::hex << std::setw(4) << std::setfill('0') << (int) servicedata_and_cbs->service_;
        request << ".";
        request << SERVICE_PARENTDOMAIN;
        servicedata_and_cbs->dns_name_ = request.str();
        if (is_open_service_request(servicedata_and_cbs->dns_name_)) {
            VSOMEIP_DEBUG << __func__ << " TLSA SERVICE REQUEST ALREADY OPEN for " << servicedata_and_cbs->dns_name_;
            return;
        }
        add_service_request(servicedata_and_cbs->dns_name_, servicedata_and_cbs);
        VSOMEIP_DEBUG << __func__ << " TLSA SERVICE REQUEST SEND for " << servicedata_and_cbs->dns_name_;
        servicedata_and_cbs->record_timestamp_callback_(servicedata_and_cbs->service_,servicedata_and_cbs->its_unicast_.to_uint(), time_metric::TLSA_SERVICE_REQUEST_SEND_);
        resolver_callback callback = std::bind(&tlsa_resolver::service_tlsa_resolve_callback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);
        dns_resolver_->resolve(request.str().c_str(), C_IN, T_TLSA, callback, _service_data);
    }

    void tlsa_resolver::request_client_tlsa_record(void* _client_data) {
        client_data_and_cbs* clientdata_and_cbs = reinterpret_cast<client_data_and_cbs*>(_client_data);
        std::stringstream request;
        request << ATTRLEAFBRANCH;
        request << "major0x" << std::hex << std::setw(2) << std::setfill('0') << (int) clientdata_and_cbs->major_;
        request << ".";
        request << "instance0x" << std::hex << std::setw(4) << std::setfill('0') << (int) clientdata_and_cbs->instance_;
        request << ".";
        request << "service0x" << std::hex << std::setw(4) << std::setfill('0') << (int) clientdata_and_cbs->service_;
        request << ".";
        request << "id0x" << std::hex << std::setw(4) << std::setfill('0') << (int) clientdata_and_cbs->client_;
        request << ".";
        request << CLIENT_PARENTDOMAIN;
        clientdata_and_cbs->dns_name_ = request.str();
        if (is_open_client_request(clientdata_and_cbs->dns_name_)) {
            VSOMEIP_DEBUG << __func__ << " TLSA CLIENT REQUEST ALREADY OPEN for " << clientdata_and_cbs->dns_name_;
            return;
        }
        add_client_request(clientdata_and_cbs->dns_name_, clientdata_and_cbs);
        VSOMEIP_DEBUG << __func__ << " TLSA CLIENT REQUEST SEND for " << clientdata_and_cbs->dns_name_;
        clientdata_and_cbs->record_timestamp_callback_(clientdata_and_cbs->service_,clientdata_and_cbs->unverified_client_ipv4_address_.to_uint(), time_metric::TLSA_CLIENT_REQUEST_SEND_);
        resolver_callback callback = std::bind(&tlsa_resolver::client_tlsa_resolve_callback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);
        dns_resolver_->resolve(clientdata_and_cbs->dns_name_.c_str(), C_IN, T_TLSA, callback, _client_data);
    }

    void tlsa_resolver::add_service_request(std::string name, service_data_and_cbs* _service_data_and_cbs) {
        std::lock_guard<std::mutex> lock(open_service_requests_mutex_);
        open_service_requests_[name] = _service_data_and_cbs;
    }

    void tlsa_resolver::add_client_request(std::string name, client_data_and_cbs* _client_data_and_cbs) {
        std::lock_guard<std::mutex> lock(open_client_requests_mutex_);
        open_client_requests_[name] = _client_data_and_cbs;
    }

    void tlsa_resolver::close_service_request(std::string name) {
        std::lock_guard<std::mutex> lock(open_service_requests_mutex_);
        open_service_requests_.erase(name);
    }

    void tlsa_resolver::close_client_request(std::string name) {
        std::lock_guard<std::mutex> lock(open_client_requests_mutex_);
        open_client_requests_.erase(name);
    }

    bool tlsa_resolver::is_open_service_request(std::string name) {
        std::lock_guard<std::mutex> lock(open_service_requests_mutex_);
        return open_service_requests_.find(name) != open_service_requests_.end();
    }

    bool tlsa_resolver::is_open_client_request(std::string name) {
        std::lock_guard<std::mutex> lock(open_client_requests_mutex_);
        return open_client_requests_.find(name) != open_client_requests_.end();
    }
} /* end namespace vsomeip_v3 */