#ifndef VSOMEIP_V3_STATISTICS_WRITER
#define VSOMEIP_V3_STATISTICS_WRITER

#include "shared_memory_parameters.hpp"
#include <map>

struct shm_remove
{
    shm_remove() { boost::interprocess::shared_memory_object::remove(SEGMENT_NAME); }
    ~shm_remove(){ boost::interprocess::shared_memory_object::remove(SEGMENT_NAME); }
};

struct mutex_remove
{
    mutex_remove() { boost::interprocess::named_mutex::remove(STATISTICS_MUTEX); }
    ~mutex_remove(){ boost::interprocess::named_mutex::remove(STATISTICS_MUTEX); }
};

struct condition_remove
{
    condition_remove() { boost::interprocess::named_condition::remove(STATISTICS_CONDITION); }
    ~condition_remove(){ boost::interprocess::named_condition::remove(STATISTICS_CONDITION); }
};

typedef std::map<std::uint16_t, std::uint32_t> service_member_map_t;

class statistics_writer {
public:
    static statistics_writer* get_instance(service_member_map_t _service_members, std::string _absolute_project_path, std::string _result_filename);
    void write_statistics();
    ~statistics_writer();
private:
    static std::mutex mutex_;
    static statistics_writer* instance_;
    static service_member_map_t service_members_;
    static std::string absolute_results_directory_path_;
    static std::string result_filename_;
    shm_remove shm_remover_;
    mutex_remove mutex_remover_;
    condition_remove condition_remover_;
    std::unordered_map<metric_key_t, std::string> time_metric_names_;
    service_statistics_map* service_composite_time_statistics_;
    statistics_writer(service_member_map_t& _service_members);
    bool entries_are_complete();
    void print_statistics();
};

#endif /* VSOMEIP_V3_STATISTICS_WRITER */