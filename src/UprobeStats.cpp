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
#include <stats_event.h>

using namespace android::uprobestats;

const std::string kGenericBpfName = std::string("GenericInstrumentation");
const int kJavaArgumentRegisterOffset = 2;
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
  std::string mapPath;
  ::uprobestats::protos::UprobestatsConfig::Task taskConfig;
  bool isGeneric;
};

void doPoll(PollArgs args) {
  auto mapPath = args.mapPath;
  auto durationSeconds = args.taskConfig.duration_seconds();
  auto duration = std::chrono::seconds(durationSeconds);
  auto startTime = std::chrono::steady_clock::now();
  auto now = startTime;
  while (now - startTime < duration) {
    auto remaining = duration - (std::chrono::steady_clock::now() - startTime);
    auto timeoutMs = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(remaining)
            .count());
    if (args.isGeneric) {
      auto result =
          bpf::pollRingBuf<bpf::CallResult>(mapPath.c_str(), timeoutMs);
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
        if (args.taskConfig.has_statsd_logging_config()) {
          auto statsd_logging_config = args.taskConfig.statsd_logging_config();
          int atom_id = statsd_logging_config.atom_id();
          if (kDebug) {
            LOG(INFO) << "attempting to write atom id: " << atom_id;
          }
          AStatsEvent *event = AStatsEvent_obtain();
          AStatsEvent_setAtomId(event, atom_id);
          for (int primitiveArgumentPosition :
               statsd_logging_config.primitive_argument_positions()) {
            int primitiveArgument = value.regs[primitiveArgumentPosition +
                                               kJavaArgumentRegisterOffset];
            if (kDebug) {
              LOG(INFO) << "writing argument value: " << primitiveArgument
                        << " from position: " << primitiveArgumentPosition;
            }
            AStatsEvent_writeInt32(event, primitiveArgument);
          }
          AStatsEvent_write(event);
          AStatsEvent_release(event);
          if (kDebug) {
            LOG(INFO) << "successfully wrote atom id: " << atom_id;
          }
        } else {
          if (kDebug) {
            LOG(INFO) << "no statsd logging config";
          }
        }
      }
    } else {
      auto result = bpf::pollRingBuf<uint32_t>(mapPath.c_str(), timeoutMs);
      for (auto value : result) {
        if (kDebug) {
          LOG(INFO) << "ringbuf result callback. value: " << value
                    << " mapPath: " << mapPath;
        }
      }
    }
    now = std::chrono::steady_clock::now();
  }
  if (kDebug) {
    LOG(INFO) << "finished polling for mapPath: " << mapPath;
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
  auto resolvedTask = config_resolver::resolveSingleTask(config.value());
  if (!resolvedTask.has_value()) {
    return 1;
  }

  if (kDebug) {
    LOG(INFO) << "Found task config: " << resolvedTask.value();
  }
  std::set<std::string> mapPaths;
  auto resolvedProbeConfigs =
      config_resolver::resolveProbes(resolvedTask.value().taskConfig);
  if (!resolvedProbeConfigs.has_value()) {
    return 1;
  }
  for (auto &resolvedProbe : resolvedProbeConfigs.value()) {
    if (kDebug) {
      LOG(INFO) << "Opening bpf perf event from probe: " << resolvedProbe;
    }
    mapPaths.insert(prefix_bpf(resolvedProbe.probeConfig.bpf_map()));
    bpf::bpfPerfEventOpen(
        resolvedProbe.filename.c_str(), resolvedProbe.offset,
        resolvedTask.value().pid,
        prefix_bpf(resolvedProbe.probeConfig.bpf_name()).c_str());
  }

  std::vector<std::thread> threads;
  for (auto mapPath : mapPaths) {
    auto poll_args = PollArgs{mapPath, resolvedTask.value().taskConfig};
    if (mapPath.find(kGenericBpfName) != std::string::npos) {
      poll_args.isGeneric = true;
    }
    if (kDebug) {
      LOG(INFO) << "Starting thread to collect results from mapPath: "
                << mapPath;
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
