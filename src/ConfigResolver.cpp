/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "uprobestats"

#include <filesystem>
#include <iostream>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <config.pb.h>
#include <json/json.h>

#include "Art.h"
#include "ConfigResolver.h"
#include "Process.h"

namespace android {
namespace uprobestats {
namespace config_resolver {

std::ostream &operator<<(std::ostream &os, const BpfPerfEventConfig &c) {
  os << "filename: " << c.filename << " offset: " << c.offset
     << " pid: " << c.pid << " bpfProgramPath: " << c.bpfProgramPath
     << " bpfMapPath: " << c.bpfMapPath;
  return os;
}

// Reads probing configuration from a file, which should be the serialized
// bytes of a UprobestatsConfig proto.
std::optional<::uprobestats::protos::UprobestatsConfig>
readConfig(std::string configFilePath) {
  std::string config_str;
  if (!android::base::ReadFileToString(configFilePath, &config_str)) {
    LOG(ERROR) << "Failed to open config file " << configFilePath;
    return {};
  }

  ::uprobestats::protos::UprobestatsConfig config;
  bool success = config.ParseFromString(config_str);
  if (!success) {
    LOG(ERROR) << "Failed to parse file " << configFilePath
               << " to UprobestatsConfig";
    return {};
  }

  return config;
}

// Parses config and returns a list of arguments for
// `android::uprobestats::bpfPerfEventOpen`
std::optional<std::vector<BpfPerfEventConfig>>
getBpfPerfEventConfigs(std::string configFilePath) {
  auto config = readConfig(configFilePath);
  if (!config.has_value()) {
    return {};
  }
  std::vector<BpfPerfEventConfig> result;
  for (auto &task : config->tasks()) {
    for (auto &probe_config : task.probe_configs()) {
      int offset = 0;
      std::string matched_file_path;
      for (auto &file_path : probe_config.file_paths()) {
        offset = art::getMethodOffsetFromOatdump(
            file_path, probe_config.method_signature());
        if (offset > 0) {
          matched_file_path = file_path;
          break;
        }
      }
      if (offset == 0) {
        LOG(ERROR) << "Unable to find method offset for "
                   << probe_config.method_signature();
        return {};
      }
      if (!task.has_target_process_name()) {
        LOG(ERROR) << "task.target_process_name is required.";
        return {};
      }

      auto process_name = task.target_process_name();
      int pid = process::getPid(process_name);
      if (pid < 0) {
        LOG(ERROR) << "Unable to find pid of " << process_name;
        return {};
      }

      auto prog_path = std::string("/sys/fs/bpf/uprobestats/") +
                       probe_config.bpf_name().c_str();

      auto map_path = std::string("/sys/fs/bpf/uprobestats/") +
                      probe_config.bpf_map().c_str();

      BpfPerfEventConfig eventConfig;
      eventConfig.filename = matched_file_path;
      eventConfig.offset = offset;
      eventConfig.pid = pid;
      eventConfig.bpfProgramPath = prog_path;
      eventConfig.bpfMapPath = map_path;
      result.push_back(eventConfig);
    }
  }
  return result;
}

} // namespace config_resolver
} // namespace uprobestats
} // namespace android