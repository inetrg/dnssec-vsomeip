#ifndef VSOMEIP_V3_TLSA_RESOLVER_H
#define VSOMEIP_V3_TLSA_RESOLVER_H

#include "dns_resolver.hpp"
#include "../include/someip_dns_parameters.hpp"

namespace vsomeip_v3 {
    class tlsa_resolver {
        private:
        std::shared_ptr<dns_resolver> dns_resolver_;
        public:
            tlsa_resolver(std::shared_ptr<dns_resolver> _dns_resolver);
            ~tlsa_resolver();
            void request_service_tlsa_record(void* _service_data);
            void request_client_tlsa_record(void* _client_data);
            void service_tlsa_resolve_callback(void* _data, int _status, int _timeouts, unsigned char* _abuf, int _alen);
            void client_tlsa_resolve_callback(void* _data, int _status, int _timeouts, unsigned char* _abuf, int _alen);
    };
} /* end namespace vsomeip_v3 */
#endif /* VSOMEIP_V3_TLSA_RESOLVER_H */