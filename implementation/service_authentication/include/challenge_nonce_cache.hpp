#ifndef VSOMEIP_V3_CHALLENGE_NONCE_CACHE_HPP
#define VSOMEIP_V3_CHALLENGE_NONCE_CACHE_HPP

#include <mutex>
#include <map>
#include <tuple>
#include <vector>
#include <deque>
#include <algorithm>
#include <boost/asio/ip/address_v4.hpp>
#include "vsomeip/primitive_types.hpp"

namespace vsomeip_v3 {

struct nonce_history_data {
    static const std::size_t k_nonce_history_size = 5;
    std::deque<std::vector<unsigned char>> nonce_history_;
    
    void push_nonce(std::vector<unsigned char>& _nonce) {
        if (_nonce.empty()) {
            return;
        }
        if (nonce_history_.size() >= k_nonce_history_size) {
            nonce_history_.pop_front();
        }
        nonce_history_.push_back(_nonce);
    };
    bool contains_nonce(std::vector<unsigned char>& _nonce) {
        return std::find(nonce_history_.begin(), nonce_history_.end(), _nonce) != nonce_history_.end();
    };
    std::vector<unsigned char> get_latest_nonce_or_empty(){
        if (nonce_history_.empty()) {
            return {};
        }
        return nonce_history_.back();   
    };
};

struct challenge_nonce_data {
    nonce_history_data nonce_history_;
    std::vector<unsigned char> certificate_data_;

    void push_nonce(std::vector<unsigned char>& _nonce) {
        nonce_history_.push_nonce(_nonce);
    };
    bool contains_nonce(std::vector<unsigned char>& _nonce) {
        return nonce_history_.contains_nonce(_nonce);
    };
    std::vector<unsigned char> get_latest_nonce_or_empty() {
        return nonce_history_.get_latest_nonce_or_empty();
    };
    bool has_certificate_data() const {
        return !certificate_data_.empty();
    }
    bool has_nonce() const {
        return !nonce_history_.nonce_history_.empty();
    }
};

class challenge_nonce_cache {
private:
    std::mutex mutex_;
    std::map<std::tuple<boost::asio::ip::address_v4, vsomeip_v3::service_t, vsomeip_v3::instance_t>, challenge_nonce_data> subscriber_challenge_nonce_map_;
    std::map<std::tuple<client_t, boost::asio::ip::address_v4, vsomeip_v3::service_t, vsomeip_v3::instance_t>, challenge_nonce_data> publisher_challenge_nonce_map_;
    std::map<std::tuple<vsomeip_v3::service_t, vsomeip_v3::instance_t>, nonce_history_data> offered_nonce_map_;
    std::tuple<boost::asio::ip::address_v4, vsomeip_v3::service_t, vsomeip_v3::instance_t> make_key_tuple(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
    std::tuple<client_t, boost::asio::ip::address_v4, vsomeip_v3::service_t, vsomeip_v3::instance_t> make_key_tuple(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
    std::tuple<vsomeip_v3::service_t, vsomeip_v3::instance_t> make_key_tuple(vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
public:
    challenge_nonce_cache();
    ~challenge_nonce_cache();
    // Methods operating on subscriber_challenge_nonce_map_
    void add_subscriber_challenge_nonce(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _nonce);
    bool has_subscriber_challenge_nonce_and_remove(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _nonce);
    void add_publisher_certificate(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _certificate_data);
    std::vector<unsigned char> get_subscriber_challenge_nonce(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
    nonce_history_data get_subscriber_challenge_nonce_history(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
    std::vector<unsigned char> get_publisher_certificate(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
    void remove_subscriber_challenge_entry(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
    // Methods operating on publisher_challenge_nonce_map_
    void add_publisher_challenge_nonce(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _nonce);
    nonce_history_data get_publisher_challenge_nonce_history(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
    bool has_publisher_challenge_nonce_and_remove(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _nonce);
    void add_subscriber_certificate(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _certificate_data);
    std::vector<unsigned char> get_publisher_challenge_nonce(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
    std::vector<unsigned char> get_subscriber_certificate(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
    void remove_publisher_challenge_entry(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
    // Methods operating on offered_nonce_map_
    void set_offered_nonce(vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _nonce);
    std::vector<unsigned char> get_offered_nonce(vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance);
};
} /* end namespace vsomeip_v3 */
#endif /* VSOMEIP_V3_CHALLENGE_NONCE_CACHE_HPP */