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
#include <thread>

#include "Bpf.h"
#include "ConfigResolver.h"

using namespace android::uprobestats;

const std::string kGenericBpfName = std::string("GenericInstrumentation");
const bool kDebug = false;

bool isUserBuild() {
  return android::base::GetProperty("ro.build.type", "unknown") == "user";
}

bool isUprobestatsEnabled() {
  return android::uprobestats::flags::enable_uprobestats();
}

const std::string bpf_path = std::string("/sys/fs/bpf/uprobestats/");
std::string prefix_bpf(std::string value) { return bpf_path + value.c_str(); }

struct PollArgs {
  std::string map_path;
  int duration_seconds;
  bool is_generic;
};

void doPoll(PollArgs args) {
  auto map_path = args.map_path;
  auto duration_seconds = args.duration_seconds;
  auto duration = std::chrono::seconds(duration_seconds);
  auto start_time = std::chrono::steady_clock::now();
  auto now = start_time;
  while (now - start_time < duration) {
    auto remaining = duration - (std::chrono::steady_clock::now() - start_time);
    auto timeout_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(remaining)
            .count());
    if (args.is_generic) {
      auto result =
          bpf::pollRingBuf<bpf::call_result>(map_path.c_str(), timeout_ms);
      for (auto value : result) {
        if (kDebug) {
          LOG(INFO) << "ringbuf generic java result...";
          LOG(INFO) << "register: pc = " << value.pc;
        }
        for (int i = 0; i < 10; i++) {
          auto reg = value.regs[i];
          if (kDebug) {
            LOG(INFO) << "register: " << i << " = " << reg;
          }
        }
      }
    } else {
      auto result = bpf::pollRingBuf<uint32_t>(map_path.c_str(), timeout_ms);
      for (auto value : result) {
        if (kDebug) {
          LOG(INFO) << "ringbuf result callback. value: " << value
                    << " map_path: " << map_path;
        }
      }
    }
    now = std::chrono::steady_clock::now();
  }
  if (kDebug) {
    LOG(INFO) << "finished polling for map_path: " << map_path;
  }
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

  auto config = config_resolver::readConfig(
      std::string("/data/misc/uprobestats-configs/") + argv[1]);
  if (!config.has_value()) {
    return 1;
  }
  auto resolved_task = config_resolver::resolveSingleTask(config.value());
  if (!resolved_task.has_value()) {
    return 1;
  }

  if (kDebug) {
    LOG(INFO) << "Found task config: " << resolved_task.value();
  }
  std::set<std::string> map_paths;
  auto resolved_probe_configs =
      config_resolver::resolveProbes(resolved_task.value().task_config);
  if (!resolved_probe_configs.has_value()) {
    return 1;
  }
  for (auto &resolved_probe : resolved_probe_configs.value()) {
    if (kDebug) {
      LOG(INFO) << "Opening bpf perf event from probe: " << resolved_probe;
    }
    map_paths.insert(prefix_bpf(resolved_probe.probe_config.bpf_map()));
    bpf::bpfPerfEventOpen(
        resolved_probe.filename.c_str(), resolved_probe.offset,
        resolved_task.value().pid,
        prefix_bpf(resolved_probe.probe_config.bpf_name()).c_str());
  }

  std::vector<std::thread> threads;
  for (auto map_path : map_paths) {
    auto poll_args = PollArgs{
        map_path, resolved_task.value().task_config.duration_seconds()};
    if (map_path.find(kGenericBpfName) != std::string::npos) {
      poll_args.is_generic = true;
    }
    if (kDebug) {
      LOG(INFO) << "Starting thread to collect results from map_path: "
                << map_path;
    }
    threads.emplace_back(doPoll, poll_args);
  }
  for (auto &thread : threads) {
    thread.join();
  }

  if (kDebug) {
    LOG(INFO) << "done.";
  }

  return 0;
}
