#include "../include/challenge_nonce_cache.hpp"
#include <iostream>
#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {
    challenge_nonce_cache::challenge_nonce_cache() {
    }

    challenge_nonce_cache::~challenge_nonce_cache() {
    }

    // Methods operating on subscriber_challenge_nonce_map_
    void challenge_nonce_cache::add_subscriber_challenge_nonce(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service,
                                vsomeip_v3::instance_t _instance, std::vector<unsigned char> _nonce) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_ipv4_address, _service, _instance);
        // check if key touple already exists, if not create a new entry
        if (!subscriber_challenge_nonce_map_.count(key_tuple)) {
            subscriber_challenge_nonce_map_[key_tuple] = challenge_nonce_data();
        }
        subscriber_challenge_nonce_map_[key_tuple].push_nonce(_nonce);
    }

    bool challenge_nonce_cache::has_subscriber_challenge_nonce_and_remove(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service,
                        vsomeip_v3::instance_t _instance, std::vector<unsigned char> _nonce) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_ipv4_address, _service, _instance);
        bool has_nonce = false;
        if (subscriber_challenge_nonce_map_.count(key_tuple) && subscriber_challenge_nonce_map_[key_tuple].has_nonce()) {
            has_nonce = subscriber_challenge_nonce_map_[key_tuple].contains_nonce(_nonce);
            if (!has_nonce) {
                VSOMEIP_WARNING << __func__ << " Nonces not matching for service: " << _service << " instance: " << _instance << " ipv4_address: " << _ipv4_address.to_string();
            }
        } else {
            VSOMEIP_WARNING << __func__ << " No entry found in subscriber_challenge_nonce_map_ for service: " << _service << " instance: " << _instance << " ipv4_address: " << _ipv4_address.to_string();
        }
        // if (has_nonce) { subscriber_challenge_nonce_map_[key_tuple].nonce_.clear(); }
        return has_nonce;
    }

    void challenge_nonce_cache::add_publisher_certificate(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service,
                        vsomeip_v3::instance_t _instance, std::vector<unsigned char> _certificate_data) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_ipv4_address, _service, _instance);
        // check if key touple already exists, if not create a new entry
        if (!subscriber_challenge_nonce_map_.count(key_tuple)) {
            subscriber_challenge_nonce_map_[key_tuple] = challenge_nonce_data();
        }
        subscriber_challenge_nonce_map_[key_tuple].certificate_data_ = _certificate_data;
    }

    std::vector<unsigned char> challenge_nonce_cache::get_subscriber_challenge_nonce(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service,
                        vsomeip_v3::instance_t _instance) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_ipv4_address, _service, _instance);
        return subscriber_challenge_nonce_map_[key_tuple].get_latest_nonce_or_empty();
    }

    nonce_history_data challenge_nonce_cache::get_subscriber_challenge_nonce_history(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service,
                        vsomeip_v3::instance_t _instance) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_ipv4_address, _service, _instance);
        return subscriber_challenge_nonce_map_[key_tuple].nonce_history_;
    }

    std::vector<unsigned char> challenge_nonce_cache::get_publisher_certificate(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service,
                        vsomeip_v3::instance_t _instance) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_ipv4_address, _service, _instance);
        return subscriber_challenge_nonce_map_[key_tuple].certificate_data_;
    }

    void challenge_nonce_cache::remove_subscriber_challenge_entry(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service,
                    vsomeip_v3::instance_t _instance) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_ipv4_address, _service, _instance);
        subscriber_challenge_nonce_map_.erase(key_tuple);
    }

    // Methods operating on publisher_challenge_nonce_map_
    void challenge_nonce_cache::add_publisher_challenge_nonce(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _nonce) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_client, _ipv4_address, _service, _instance);
        // check if key touple already exists, if not create a new entry
        if (!publisher_challenge_nonce_map_.count(key_tuple)) {
            publisher_challenge_nonce_map_[key_tuple] = challenge_nonce_data();
        }
        publisher_challenge_nonce_map_[key_tuple].push_nonce(_nonce);
    }

    bool challenge_nonce_cache::has_publisher_challenge_nonce_and_remove(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _nonce) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_client, _ipv4_address, _service, _instance);
        bool has_nonce = false;
        if (publisher_challenge_nonce_map_.count(key_tuple) && publisher_challenge_nonce_map_[key_tuple].has_nonce()) {
            has_nonce = publisher_challenge_nonce_map_[key_tuple].contains_nonce(_nonce);
            if (!has_nonce) {
                VSOMEIP_WARNING << __func__ << " Nonces not matching for client: " << _client << " service: " << _service << " instance: " << _instance << " ipv4_address: " << _ipv4_address.to_string();
            }
        } else {
            VSOMEIP_WARNING << __func__ << " No entry found in publisher_challenge_nonce_map_ for client: " << _client << " service: " << _service << " instance: " << _instance << " ipv4_address: " << _ipv4_address.to_string();
        }
        // if (has_nonce) { publisher_challenge_nonce_map_[key_tuple].nonce_.clear(); }
        return has_nonce;
    }

    void challenge_nonce_cache::add_subscriber_certificate(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _certificate_data) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_client, _ipv4_address, _service, _instance);
        publisher_challenge_nonce_map_[key_tuple].certificate_data_ = _certificate_data;
    }

    std::vector<unsigned char> challenge_nonce_cache::get_publisher_challenge_nonce(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_client, _ipv4_address, _service, _instance);
        return publisher_challenge_nonce_map_[key_tuple].get_latest_nonce_or_empty();
    }

    nonce_history_data challenge_nonce_cache::get_publisher_challenge_nonce_history(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_client, _ipv4_address, _service, _instance);
        return publisher_challenge_nonce_map_[key_tuple].nonce_history_;
    }

    std::vector<unsigned char> challenge_nonce_cache::get_subscriber_certificate(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_client, _ipv4_address, _service, _instance);
        return publisher_challenge_nonce_map_[key_tuple].certificate_data_;
    }

    void challenge_nonce_cache::remove_publisher_challenge_entry(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_client, _ipv4_address, _service, _instance);
        publisher_challenge_nonce_map_.erase(key_tuple);
    }

    // Methods operating on offered_nonce_map_    
    void challenge_nonce_cache::set_offered_nonce(vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance, std::vector<unsigned char> _nonce) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_service, _instance);
        // check if key touple already exists, if not create a new entry
        if (!offered_nonce_map_.count(key_tuple)) {
            offered_nonce_map_[key_tuple] = nonce_history_data();
        }
        offered_nonce_map_[key_tuple].push_nonce(_nonce);
    }

    std::vector<unsigned char> challenge_nonce_cache::get_offered_nonce(vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto key_tuple = make_key_tuple(_service, _instance);
        return offered_nonce_map_[key_tuple].get_latest_nonce_or_empty();
    }

    // Make key tuple methods
    std::tuple<boost::asio::ip::address_v4, vsomeip_v3::service_t,
                        vsomeip_v3::instance_t> challenge_nonce_cache::make_key_tuple(boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service,
                        vsomeip_v3::instance_t _instance) {
        return std::make_tuple(_ipv4_address, _service, _instance);
    }

    std::tuple<client_t, boost::asio::ip::address_v4, vsomeip_v3::service_t, vsomeip_v3::instance_t> challenge_nonce_cache::make_key_tuple(client_t _client, boost::asio::ip::address_v4 _ipv4_address, vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance) {
        return std::make_tuple(_client, _ipv4_address, _service, _instance);
    }

    std::tuple<vsomeip_v3::service_t, vsomeip_v3::instance_t> challenge_nonce_cache::make_key_tuple(vsomeip_v3::service_t _service, vsomeip_v3::instance_t _instance) {
        return std::make_tuple(_service, _instance);
    }
} /* end namespace vsomeip_v3 */