#include "../include/requester_authentication_cache.hpp"

namespace vsomeip_v3 {

requester_authentication_cache::requester_authentication_cache() {
}

requester_authentication_cache::~requester_authentication_cache() {
}

bool requester_authentication_cache::has_validated_subscription(
        client_t _client,
        const boost::asio::ip::address_v4 &_requester,
        service_t _service, instance_t _instance,
        major_version_t _major) const {
    std::lock_guard<std::mutex> lockguard(mutex_);
    return validated_subscriptions_.find(make_validated_subscription_key(
            _client, _requester, _service, _instance, _major))
            != validated_subscriptions_.end();
}

bool requester_authentication_cache::mark_validated_subscription(
        client_t _client,
        const boost::asio::ip::address_v4 &_requester,
        service_t _service, instance_t _instance,
        major_version_t _major) {
    std::lock_guard<std::mutex> lockguard(mutex_);
    return validated_subscriptions_.insert(make_validated_subscription_key(
            _client, _requester, _service, _instance, _major)).second;
}

bool requester_authentication_cache::has_validated_subscription_ack(
        const boost::asio::ip::address_v4 &_requester,
        service_t _service, instance_t _instance,
        major_version_t _major) const {
    std::lock_guard<std::mutex> lockguard(mutex_);
    return validated_subscription_acks_.find(make_validated_subscription_ack_key(
            _requester, _service, _instance, _major))
            != validated_subscription_acks_.end();
}

bool requester_authentication_cache::mark_validated_subscription_ack(
        const boost::asio::ip::address_v4 &_requester,
        service_t _service, instance_t _instance,
        major_version_t _major) {
    std::lock_guard<std::mutex> lockguard(mutex_);
    return validated_subscription_acks_.insert(make_validated_subscription_ack_key(
            _requester, _service, _instance, _major)).second;
}

void requester_authentication_cache::remove_requester(
        const boost::asio::ip::address_v4 &_requester) {
    std::lock_guard<std::mutex> lockguard(mutex_);

    for (auto it = validated_subscriptions_.begin();
            it != validated_subscriptions_.end();) {
        if (std::get<1>(*it) == _requester) {
            it = validated_subscriptions_.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = validated_subscription_acks_.begin();
            it != validated_subscription_acks_.end();) {
        if (std::get<0>(*it) == _requester) {
            it = validated_subscription_acks_.erase(it);
        } else {
            ++it;
        }
    }
}

void requester_authentication_cache::clear() {
    std::lock_guard<std::mutex> lockguard(mutex_);
    validated_subscriptions_.clear();
    validated_subscription_acks_.clear();
}

requester_authentication_cache::validated_subscription_key_t
requester_authentication_cache::make_validated_subscription_key(
        client_t _client,
        const boost::asio::ip::address_v4 &_requester,
        service_t _service, instance_t _instance,
        major_version_t _major) const {
    return std::make_tuple(_client, _requester, _service, _instance, _major);
}

requester_authentication_cache::validated_subscription_ack_key_t
requester_authentication_cache::make_validated_subscription_ack_key(
        const boost::asio::ip::address_v4 &_requester,
        service_t _service, instance_t _instance,
        major_version_t _major) const {
    return std::make_tuple(_requester, _service, _instance, _major);
}

} // namespace vsomeip_v3
