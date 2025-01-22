#ifndef VSOMEIP_V3_STATISTICS_RECORDER
#define VSOMEIP_V3_STATISTICS_RECORDER

#include "shared_memory_parameters.hpp"
#include <set>

typedef std::unordered_map<metric_key_t, metric_value_t> time_stats_t;
typedef std::unordered_map<host_key_t, time_stats_t> host_time_stats_t;
typedef std::unordered_map<service_id_t, host_time_stats_t> service_host_time_stats_t;

namespace vsomeip_v3 {
    class configuration;
}

class statistics_recorder
{
public:
    static statistics_recorder* get_instance();
    void set_configuration(std::shared_ptr<vsomeip_v3::configuration> _configuration);
    void initialize_statistics(uint64_t _init_start);
    void record_timestamp_for_service(service_id_t _service_id, uint32_t _host_ip, time_metric _time_metric);
    void record_custom_timestamp_for_service(service_id_t _service_id, uint32_t _host_ip, time_metric _time_metric, uint64_t _timestamp);
    void contribute_statistics();
    ~statistics_recorder();
private:
    static std::mutex mutex_;
    static statistics_recorder* instance_;
    service_host_time_stats_t time_statistics_;
    std::unordered_map<service_id_t, std::size_t> required_hosts_;
    std::unordered_map<service_id_t, std::set<host_key_t>> entries_complete_;
    service_statistics_map* service_composite_time_statistics_;
    std::shared_ptr<vsomeip_v3::configuration> configuration_;
    bool already_contributed_ = false;
    bool initialized_ = false;
    bool check_services_complete();
    statistics_recorder();
};

#endif /* VSOMEIP_V3_STATISTICS_RECORDER */