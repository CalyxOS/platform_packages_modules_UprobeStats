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

  auto eventConfigs = config_resolver::getBpfPerfEventConfigs(
      std::string("/data/misc/uprobestats-configs/") + argv[1]);
  if (!eventConfigs.has_value()) {
    return 1;
  }

  std::set<std::string> map_paths;
  for (auto &eventConfig : eventConfigs.value()) {
    LOG(INFO) << "Opening bpf perf event from config: " << eventConfig;
    map_paths.insert(eventConfig.bpfMapPath);
    bpf::bpfPerfEventOpen(eventConfig.filename.c_str(), eventConfig.offset,
                          eventConfig.pid, eventConfig.bpfProgramPath.c_str());
  }

  sleep(60);
  for (auto map_path : map_paths) {
    bpf::printRingBuf(map_path.c_str());
  }

  return 0;
}
