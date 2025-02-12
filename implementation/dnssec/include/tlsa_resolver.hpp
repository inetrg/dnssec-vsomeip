#ifndef VSOMEIP_V3_TLSA_RESOLVER_H
#define VSOMEIP_V3_TLSA_RESOLVER_H

#include "dns_resolver.hpp"
#include "../include/someip_dns_parameters.hpp"
#include <map>

namespace vsomeip_v3 {
    class tlsa_resolver {
        private:
        std::shared_ptr<dns_resolver> dns_resolver_;
        std::map<std::string, service_data_and_cbs*> open_service_requests_;
        std::mutex open_service_requests_mutex_;
        std::map<std::string, client_data_and_cbs*> open_client_requests_;
        std::mutex open_client_requests_mutex_;
        public:
            tlsa_resolver(std::shared_ptr<dns_resolver> _dns_resolver);
            ~tlsa_resolver();
            void request_service_tlsa_record(void* _service_data);
            void request_client_tlsa_record(void* _client_data);
            void service_tlsa_resolve_callback(void* _data, int _status, int _timeouts, unsigned char* _abuf, int _alen);
            void client_tlsa_resolve_callback(void* _data, int _status, int _timeouts, unsigned char* _abuf, int _alen);
        private:
            void add_service_request(std::string name, service_data_and_cbs* _service_data_and_cbs);
            void add_client_request(std::string name, client_data_and_cbs* _client_data_and_cbs);
            void close_service_request(std::string name);
            void close_client_request(std::string name);
            bool is_open_service_request(std::string name);
            bool is_open_client_request(std::string name);
    };
} /* end namespace vsomeip_v3 */
#endif /* VSOMEIP_V3_TLSA_RESOLVER_H */