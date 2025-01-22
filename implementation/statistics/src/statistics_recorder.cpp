#include "../include/statistics_recorder.hpp"

#include <iostream>
#include <stdexcept>
#include "../../configuration/include/configuration.hpp"

std::mutex statistics_recorder::mutex_;
statistics_recorder* statistics_recorder::instance_;

statistics_recorder* statistics_recorder::get_instance() {
    std::lock_guard<std::mutex> lock_guard(mutex_);
    if(instance_ == nullptr) {
        instance_ = new statistics_recorder();
    }
    return instance_;
}

void statistics_recorder::set_configuration(std::shared_ptr<vsomeip_v3::configuration> _configuration) {
    configuration_ = _configuration;
}

void statistics_recorder::initialize_statistics(uint64_t _init_start) {
    if(initialized_) {
        return;
    }
    if(!configuration_) {
        throw std::runtime_error("Configuration not set for statistics recorder");
    }
    auto provided_services = configuration_->get_local_services();
    for (const auto& service : provided_services) {
        uint16_t service_id = service.first;
        uint16_t instance_id = service.second;
        auto clients = configuration_->get_client_certificates(service_id, instance_id);
        required_hosts_[service_id] = clients.size();
    }
    auto required_services = configuration_->get_required_services();
    auto local_host_id = configuration_->get_unicast_address().to_v4().to_uint();
    for (const auto& service : required_services) {
        service_id_t service_id = service.first;
        required_hosts_[service_id] = 1;
        record_custom_timestamp_for_service(service_id, local_host_id, time_metric::SUBSCRIBER_APP_INITIALIZATION_START_, _init_start);
        record_timestamp_for_service(service_id, local_host_id, time_metric::SUBSCRIBER_APP_INITIALIZATION_END_);
    }
    initialized_ = true;
}

statistics_recorder::statistics_recorder() {
}

statistics_recorder::~statistics_recorder() {
}

void statistics_recorder::record_custom_timestamp_for_service(service_id_t _service_id, uint32_t _host_ip, time_metric _time_metric, uint64_t _timestamp) {
    // check if stats for service are complete and mark them
    std::lock_guard<std::mutex> lock_guard(mutex_);
    if (!time_statistics_.count(_service_id)) {
        time_statistics_[_service_id] = host_time_stats_t();
    }
    if (!time_statistics_[_service_id].count(_host_ip)) {
        time_statistics_[_service_id][_host_ip] = time_stats_t();
    }
    if (!time_statistics_[_service_id][_host_ip].count(_time_metric)) {
        // only record the timestamp if it is not already recorded
        time_statistics_[_service_id][_host_ip][_time_metric] = _timestamp;
    }
}

void statistics_recorder::record_timestamp_for_service(service_id_t _service_id, uint32_t _host_ip, time_metric _time_metric) {
    metric_value_t time = static_cast<metric_value_t>(std::chrono::system_clock::now().time_since_epoch().count());
    record_custom_timestamp_for_service(_service_id, _host_ip, _time_metric, time);
}

void statistics_recorder::contribute_statistics() {
    bool waited_for_shm = false;
    for (bool shared_objects_initialized = false; !shared_objects_initialized;) {
        try {
            boost::interprocess::named_condition condition(boost::interprocess::open_only, STATISTICS_CONDITION);
            boost::interprocess::named_mutex mutex(boost::interprocess::open_only, STATISTICS_MUTEX);
            boost::interprocess::managed_shared_memory segment(boost::interprocess::open_only, SEGMENT_NAME);
            void_allocator void_allocator_instance(segment.get_segment_manager());

            while (!(service_composite_time_statistics_ = segment.find<service_statistics_map>(TIME_STATISTICS_MAP_NAME).first)) {
                waited_for_shm = true;
                boost::interprocess::scoped_lock<boost::interprocess::named_mutex> lock(mutex);
                condition.wait(lock);
                std::cout << "[<statistics_recorder>] (" << __func__ << ") shared maps not intialized yet" << std::endl;
            }
            if(waited_for_shm) {
                std::cout << "[<statistics_recorder>] (" << __func__ << ") resume composing" << std::endl;
            }
            
            {
                boost::interprocess::scoped_lock<boost::interprocess::named_mutex> lock(mutex);
                for (auto service_entry : time_statistics_) {
                    service_id_t service_id = service_entry.first;
                    if (service_composite_time_statistics_->count(service_id) == 0) {
                        service_composite_time_statistics_->insert({service_id, statistics_map_data(void_allocator_instance)});
                    }
                    auto composite_time_statistics_ = &(service_composite_time_statistics_->at(service_id).statistics_map_);
                    for(auto host_entry : service_entry.second) {
                        metrics_map_data* mapped_metrics_map;
                        if(composite_time_statistics_->count(host_entry.first)) {
                            mapped_metrics_map = &composite_time_statistics_->at(host_entry.first);
                        } else {
                            metrics_map_data metrics_map_data_var = metrics_map_data(void_allocator_instance);
                            mapped_metrics_map = &metrics_map_data_var;
                        }
                        for(auto metrics_entry : host_entry.second) {
                            mapped_metrics_map->metrics_map_.insert({metrics_entry.first, metrics_entry.second});
                        }
                        composite_time_statistics_->insert({host_entry.first, *mapped_metrics_map});
                    }
                }
                shared_objects_initialized = true;
            }
            condition.notify_one();
        } catch (boost::interprocess::interprocess_exception& interprocess_exception) {
            std::cerr << __func__ << interprocess_exception.what() << std::endl;
            std::cout << "[<statistics_recorder>] (" << __func__ << ") shared objects may not created yet or segment size is not enough. Examine error message for exact cause." << std::endl;
            sleep(1);
        }
    }
}