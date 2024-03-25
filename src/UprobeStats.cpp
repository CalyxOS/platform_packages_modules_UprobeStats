/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android_uprobestats_flags.h>
#include <config.pb.h>
#include <iostream>
#include <json/json.h>
#include <stdio.h>

#include <string>

#include "BpfUtilities.h"
#include "ProcessInfoRetriever.h"

// Reads probing configuration from a file, which should be the serialized
// bytes of a UprobestatsConfig proto.
std::optional<uprobestats::protos::UprobestatsConfig>
readConfig(std::string configFilePath) {
  std::string config_str;
  if (!android::base::ReadFileToString(configFilePath, &config_str)) {
    LOG(ERROR) << "Failed to open config file " << configFilePath;
    return {};
  }

  uprobestats::protos::UprobestatsConfig config;
  bool success = config.ParseFromString(config_str);
  if (!success) {
    LOG(ERROR) << "Failed to parse file " << configFilePath
               << " to UprobestatsConfig";
    return {};
  }

  return config;
}

// Uses the oatdump binary to retrieve the offset for a given method
int getMethodOffsetFromOatdump(std::string oat_file,
                               std::string method_signature) {
  // call oatdump and collect stdout
  auto command = std::string("oatdump --oat-file=") + oat_file +
                 std::string(" --dump-method-and-offset-as-json");
  FILE *pipe = popen(command.c_str(), "r");
  char buffer[256];
  std::string result = "";
  while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
    result += buffer;
  }
  pclose(pipe);

  // find the first json blob with a method matching the provided signature
  std::stringstream ss(result);
  std::string line;
  Json::Reader reader;
  while (std::getline(ss, line)) {
    Json::Value entry;
    bool success = reader.parse(line, entry);
    if (success) {
      auto found_method_signature = entry["method"].asString();
      if (found_method_signature == method_signature) {
        auto hex_string = entry["offset"].asString();
        int offset;
        std::istringstream stream(hex_string);
        stream >> std::hex >> offset;
        return offset;
      }
    }
  }

  return 0;
}

struct BpfPerfEventConfig {
  std::string filename;
  int offset;
  int pid;
  std::string bpfProgramPath;
};

// Parses config and returns a list of arguments for
// `android::uprobestats::bpfPerfEventOpen`
std::optional<std::vector<BpfPerfEventConfig>>
getBpfPerfEventConfigs(uprobestats::protos::UprobestatsConfig config) {
  std::vector<BpfPerfEventConfig> result;
  for (auto &task : config.tasks()) {
    for (auto &probe_config : task.probe_configs()) {
      int offset = 0;
      std::string matched_file_path;
      for (auto &file_path : probe_config.file_paths()) {
        offset = getMethodOffsetFromOatdump(file_path,
                                            probe_config.method_signature());
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
      int pid = android::uprobestats::getPid(process_name);
      if (pid < 0) {
        LOG(ERROR) << "Unable to find pid of " << process_name;
        return {};
      }

      auto prog_path = std::string("/sys/fs/bpf/uprobestats/") +
                       probe_config.bpf_name().c_str();

      BpfPerfEventConfig eventConfig;
      eventConfig.filename = matched_file_path;
      eventConfig.offset = offset;
      eventConfig.pid = pid;
      eventConfig.bpfProgramPath = prog_path;
      result.push_back(eventConfig);
    }
  }
  return result;
}

bool isUserBuild() {
    return android::base::GetProperty("ro.build.type", "unknown") == "user";
}

int main(int argc, char **argv) {
    if (isUserBuild()) {
        // TODO(296108553): See if we could avoid shipping this binary on user
        // builds.
        LOG(ERROR) << "uprobestats disabled on user build. Exiting.";
        return 1;
    }
    if (!android::uprobestats::flags::enable_uprobestats()) {
        LOG(ERROR) << "uprobestats disabled by flag. Exiting.";
        return 1;
    }
    if (argc < 2) {
        LOG(ERROR) << "Not enough command line arguments. Exiting.";
        return 1;
    }

    std::optional<uprobestats::protos::UprobestatsConfig> config =
        readConfig(std::string("/data/misc/uprobestats-configs/") + argv[1]);
    if (!config.has_value()) {
      LOG(ERROR) << "Failed to parse input file";
      return 1;
    }
    auto eventConfigs = getBpfPerfEventConfigs(config.value());
    if (!eventConfigs.has_value()) {
      return 1;
    }

    for (auto &eventConfig : eventConfigs.value()) {
      android::uprobestats::bpfPerfEventOpen(
          eventConfig.filename.c_str(), eventConfig.offset, eventConfig.pid,
          eventConfig.bpfProgramPath.c_str());
    }

    // TODO should this be in the proto or based on bpf_name?
    const char *map_path =
        "/sys/fs/bpf/uprobestats/map_BitmapAllocation_output_buf";

    sleep(10);
    android::uprobestats::printRingBuf(map_path);
    return 0;
}
