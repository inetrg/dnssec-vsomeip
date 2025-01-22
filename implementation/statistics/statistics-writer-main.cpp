#include "include/statistics_writer.hpp"
#include <iostream>
#include <memory>
#include <string>
#include <map>

int main (int argc, char* argv[]) {
    if(argc < 4 or argc >= 6) {
      std::cerr << "Usage: " + std::string(argv[0]) + "[<service_ids>] <member_counts> <absolute_results_directory_path> <result_file_name>\n";
      std::cerr << "  Example: " + std::string(argv[0]) + "'[1,5]' '[1,20]' /path/to/results/directory myfilename\n";
      std::cerr << std::to_string(argc) + " arguments provided\n";
      return 1;
    }
    std::string absolute_results_directory_path = "";
    std::string result_filename = "";
    service_member_map_t service_id_member_count_map;

    // std::cerr << "argc: " << argc << std::endl;
    // for (int i = 0; i < argc; i++) {
    //   std::cerr << "argv[" << i << "]: " << argv[i] << std::endl;
    // }

    if (argc == 4) {
      std::uint16_t service_id = 0;
      std::uint32_t member_count = static_cast<std::uint32_t>(std::stoi(argv[1]));
      absolute_results_directory_path = std::string(argv[2]);
      result_filename = std::string(argv[3]);
      service_id_member_count_map[service_id] = member_count;
    } else {
      // new implementation uses a service_id list and a member_count list to support multiple service_ids with different member_counts
      std::string service_ids(argv[1]);
      std::string member_counts(argv[2]);
      absolute_results_directory_path = argv[3];
      result_filename = std::string(argv[4]);
      if (service_ids.empty() or member_counts.empty()) {
        std::cerr << "service_ids and member_counts must not be empty\n";
        return 1;
      }
      // remove brackets from service_ids and member_counts
      service_ids.erase(0, 1);
      service_ids.erase(service_ids.size()-1, 1);
      member_counts.erase(0, 1);
      member_counts.erase(member_counts.size()-1, 1);
      // remove all spaces from service_ids and member_counts
      service_ids.erase(std::remove(service_ids.begin(), service_ids.end(), ' '), service_ids.end());
      member_counts.erase(std::remove(member_counts.begin(), member_counts.end(), ' '), member_counts.end());
      // split service_ids and member_counts by comma and create a map with service_id(key) and member_count (value)
      
      std::string delimiter(",");
      std::string service_id_token;
      std::string member_count_token;
      size_t service_pos = 0;
      size_t member_pos = 0;
      while ((service_pos = service_ids.find(delimiter)) != std::string::npos &&
         (member_pos = member_counts.find(delimiter)) != std::string::npos) {
        service_id_token = service_ids.substr(0, service_pos);
        member_count_token = member_counts.substr(0, member_pos);
        if (service_id_token.empty() || member_count_token.empty()) {
          std::cerr << "service_id and member_count must not be empty\n";
          return 1;
        }
        if (service_id_token.find("0x") != std::string::npos) {
          service_id_token = std::to_string(std::stoi(service_id_token, nullptr, 16));
        }
        service_id_member_count_map[static_cast<std::uint16_t>(std::stoi(service_id_token))] = std::stoi(member_count_token);
        service_ids.erase(0, service_pos + delimiter.length());
        member_counts.erase(0, member_pos + delimiter.length());
      }
      // Add the last pair after the loop
      if (!service_ids.empty() && !member_counts.empty()) {
        service_id_member_count_map[static_cast<std::uint16_t>(std::stoi(service_ids))] = static_cast<std::uint32_t>(std::stoi(member_counts));
      }
    }
    std::string slash_char("/");
    if (absolute_results_directory_path.compare(absolute_results_directory_path.length()-1,1,slash_char)) {
        absolute_results_directory_path += "/";
    }

    if (service_id_member_count_map.empty()) {
      std::cerr << "member_count must be greater than 0\n";
      return 1;
    }
    // std::cerr << "service ids and members: " << std::endl;
    // for (auto const& x : service_id_member_count_map) {
    //   std::cerr << x.first << ": " << x.second << std::endl;
    // }
    // std::cerr << "absolute_results_directory_path: " << absolute_results_directory_path << std::endl;
    // std::cerr << "result_filename: " << result_filename << std::endl;

    std::unique_ptr<statistics_writer> sw(statistics_writer::get_instance(service_id_member_count_map, absolute_results_directory_path, result_filename));
    sw->write_statistics();
    return 0;
}