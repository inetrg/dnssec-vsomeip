#ifndef VSOMEIP_V3_REQUESTER_AUTHENTICATION_CACHE_HPP
#define VSOMEIP_V3_REQUESTER_AUTHENTICATION_CACHE_HPP

#include <mutex>
#include <set>
#include <tuple>

#include <boost/asio/ip/address_v4.hpp>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {

class requester_authentication_cache {
public:
    requester_authentication_cache();
    ~requester_authentication_cache();

    requester_authentication_cache(requester_authentication_cache const&) = delete;
    requester_authentication_cache(requester_authentication_cache&&) = delete;
    requester_authentication_cache& operator=(requester_authentication_cache const&) = delete;
    requester_authentication_cache& operator=(requester_authentication_cache&&) = delete;

    bool has_validated_subscription(client_t _client,
            const boost::asio::ip::address_v4 &_requester,
            service_t _service, instance_t _instance,
            major_version_t _major) const;
    bool mark_validated_subscription(client_t _client,
            const boost::asio::ip::address_v4 &_requester,
            service_t _service, instance_t _instance,
            major_version_t _major);

    bool has_validated_subscription_ack(
            const boost::asio::ip::address_v4 &_requester,
            service_t _service, instance_t _instance,
            major_version_t _major) const;
    bool mark_validated_subscription_ack(
            const boost::asio::ip::address_v4 &_requester,
            service_t _service, instance_t _instance,
            major_version_t _major);

    void remove_requester(const boost::asio::ip::address_v4 &_requester);
    void clear();

private:
    typedef std::tuple<client_t, boost::asio::ip::address_v4,
            service_t, instance_t, major_version_t> validated_subscription_key_t;
    typedef std::tuple<boost::asio::ip::address_v4,
            service_t, instance_t, major_version_t> validated_subscription_ack_key_t;

    validated_subscription_key_t make_validated_subscription_key(client_t _client,
            const boost::asio::ip::address_v4 &_requester,
            service_t _service, instance_t _instance,
            major_version_t _major) const;
    validated_subscription_ack_key_t make_validated_subscription_ack_key(
            const boost::asio::ip::address_v4 &_requester,
            service_t _service, instance_t _instance,
            major_version_t _major) const;

    mutable std::mutex mutex_;
    std::set<validated_subscription_key_t> validated_subscriptions_;
    std::set<validated_subscription_ack_key_t> validated_subscription_acks_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_REQUESTER_AUTHENTICATION_CACHE_HPP
