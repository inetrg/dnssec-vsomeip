#include <inttypes.h>
#include <memory>
#include <iostream>
#include <functional>
#include "../implementation/dnssec/include/tlsa_resolver.hpp"
#include "../implementation/service_authentication/include/crypto_operator.hpp"
#include <condition_variable>
#include <mutex>
#include <boost/asio/ip/address_v4.hpp>

using namespace vsomeip_v3;
class callbacks {
public:
int numRequest;
std::string processId;
int count = 0;
std::mutex mtx;
std::condition_variable cv;
callbacks(int numRequest_, std::string processId_) : numRequest(numRequest_), processId(processId_), count(0) {}
~callbacks() {}
// record timestamp callback
void record_timestamp_callback(service_t _service, uint32_t _ipv4_address, time_metric _time_metric) {
    (void)_service;
    (void)_ipv4_address;
    (void)_time_metric;
    // print the result
    // std::cout << "Service: " << _service << " IPv4 Address: " << _ipv4_address << " Time Metric: " << _time_metric << std::endl;
}

// add publisher certificate callback
void add_publisher_certificate_callback(boost::asio::ip::address_v4 _ipv4_address, service_t _service, instance_t _instance, std::vector<unsigned char> _certificate_association_data) {
    (void)_ipv4_address;
    (void)_service;
    (void)_instance;
    (void)_certificate_association_data;
    // print the result
    // std::cout << "IPv4 Address: " << _ipv4_address << " Service: " << _service << " Instance: " << _instance << " Certificate Association Data: ";
    // for (auto i : _certificate_association_data) {
    //     std::cout << i;
    // }
    // std::cout << std::endl;
}

// validate subscribe ack and verify signature callback
void validate_subscribe_ack_and_verify_signature_callback(boost::asio::ip::address_v4 _ipv4_address, service_t _service, instance_t _instance, major_version_t _major) {
    (void)_ipv4_address;
    (void)_service;
    (void)_instance;
    (void)_major;
    // print the result
    ++count;
    std::cout << "finished (process " << processId << ", count " << count << ")" << std::endl;
    if (count >= numRequest) {
        std::cout << "success (process " << processId << ", num_requests " << numRequest << ")" << std::endl;
        cv.notify_all();
    }
}

// Funktion zum Warten auf die Bedingungsvariable
void wait_for_requests() {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [this] { return count >= numRequest; });
}

};

service_data_and_cbs* create_service_data(crypto_operator* crypto_operator_, callbacks* callbacks_) {
    // create a service data structure to look up 
    service_data_and_cbs* service_data = new service_data_and_cbs();
    service_data->service_ = 0x0001;
    service_data->instance_ = 0x0001;
    service_data->major_ = 0x00;
    service_data->minor_ = 0x00000000;
    service_data->ipv4_address_ = boost::asio::ip::address_v4::from_string("10.0.0.1");
    service_data->add_publisher_certificate_callback_ = std::bind(&callbacks::add_publisher_certificate_callback, callbacks_, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
    service_data->validate_subscribe_ack_and_verify_signature_callback_ = std::bind(&callbacks::validate_subscribe_ack_and_verify_signature_callback, callbacks_, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
    service_data->record_timestamp_callback_ = std::bind(&callbacks::record_timestamp_callback, callbacks_, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    service_data->convert_der_to_pem_callback_ = std::bind(&crypto_operator::convert_der_to_pem, crypto_operator_, std::placeholders::_1);
    return service_data;
}

// main launch function to test the DNS resolver 
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <process_id>" << std::endl;
        return 1;
    }

    int numRequest = 1;
    std::string process_id = argv[1];

    crypto_operator crypto_operator_;
    callbacks callbacks_(numRequest, process_id);

    // set dns ip to local ip: 172.20.140.234
    uint32_t dns_ip = 0xAC148CEA; // 0xAC=172 0x14=20 0x8C=140 0xEA=234

    // create a new DNS resolver for tlsa records
    std::shared_ptr<dns_resolver> dns_resolver_ = std::make_shared<dns_resolver>(dns_ip, process_id);
    std::shared_ptr<tlsa_resolver> tlsa_resolver_ = std::make_shared<tlsa_resolver>(dns_resolver_);

    // request the service tlsa record
    for (int i = 0; i < numRequest; i++) {
        tlsa_resolver_->request_service_tlsa_record(create_service_data(&crypto_operator_, &callbacks_));
    }
    callbacks_.wait_for_requests();
}
