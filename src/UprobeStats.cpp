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
#include <stdio.h>
#include <string>

#include "Bpf.h"
#include "ConfigResolver.h"

using namespace android::uprobestats;

bool isUserBuild() {
  return android::base::GetProperty("ro.build.type", "unknown") == "user";
}

bool isUprobestatsEnabled() {
  return android::uprobestats::flags::enable_uprobestats();
}

const std::string bpf_path = std::string("/sys/fs/bpf/uprobestats/");
std::string prefix_bpf(std::string value) { return bpf_path + value.c_str(); }

int main(int argc, char **argv) {
  if (isUserBuild()) {
    // TODO(296108553): See if we could avoid shipping this binary on user
    // builds.
    LOG(ERROR) << "uprobestats disabled on user build. Exiting.";
    return 1;
  }
  if (!isUprobestatsEnabled()) {
    LOG(ERROR) << "uprobestats disabled by flag. Exiting.";
    return 1;
  }
  if (argc < 2) {
    LOG(ERROR) << "Not enough command line arguments. Exiting.";
    return 1;
  }

  auto config = config_resolver::readConfig(
      std::string("/data/misc/uprobestats-configs/") + argv[1]);
  if (!config.has_value()) {
    return 1;
  }
  auto resolved_task = config_resolver::resolveSingleTask(config.value());
  if (!resolved_task.has_value()) {
    return 1;
  }

  LOG(INFO) << "Found task config: " << resolved_task.value();
  std::set<std::string> map_paths;
  auto resolved_probe_configs =
      config_resolver::resolveProbes(resolved_task.value().task_config);
  if (!resolved_probe_configs.has_value()) {
    return 1;
  }
  for (auto &resolved_probe : resolved_probe_configs.value()) {
    LOG(INFO) << "Opening bpf perf event from probe: " << resolved_probe;
    map_paths.insert(prefix_bpf(resolved_probe.probe_config.bpf_map()));
    bpf::bpfPerfEventOpen(
        resolved_probe.filename.c_str(), resolved_probe.offset,
        resolved_task.value().pid,
        prefix_bpf(resolved_probe.probe_config.bpf_name()).c_str());
  }

  sleep(resolved_task.value().task_config.duration_seconds());
  for (auto map_path : map_paths) {
    bpf::printRingBuf(map_path.c_str());
  }

  return 0;
}
