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

#define LOG_IF_DEBUG(msg)                                                      \
  do {                                                                         \
    if (kDebug) {                                                              \
      LOG(INFO) << msg;                                                        \
    }                                                                          \
  } while (0)

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
        LOG_IF_DEBUG("ringbuf generic java result...");
        LOG_IF_DEBUG("register: pc = " << value.pc);
        for (int i = 0; i < 10; i++) {
          auto reg = value.regs[i];
          LOG_IF_DEBUG("register: " << i << " = " << reg);
        }
        if (args.taskConfig.has_statsd_logging_config()) {
          auto statsd_logging_config = args.taskConfig.statsd_logging_config();
          int atom_id = statsd_logging_config.atom_id();
          LOG_IF_DEBUG("attempting to write atom id: " << atom_id);
          AStatsEvent *event = AStatsEvent_obtain();
          AStatsEvent_setAtomId(event, atom_id);
          for (int primitiveArgumentPosition :
               statsd_logging_config.primitive_argument_positions()) {
            int primitiveArgument = value.regs[primitiveArgumentPosition +
                                               kJavaArgumentRegisterOffset];
            LOG_IF_DEBUG("writing argument value: "
                         << primitiveArgument
                         << " from position: " << primitiveArgumentPosition);
            AStatsEvent_writeInt32(event, primitiveArgument);
          }
          AStatsEvent_write(event);
          AStatsEvent_release(event);
          LOG_IF_DEBUG("successfully wrote atom id: " << atom_id);
        } else {
          LOG_IF_DEBUG("no statsd logging config");
        }
      }
    } else {
      auto result = bpf::pollRingBuf<uint64_t>(mapPath.c_str(), timeoutMs);
      for (auto value : result) {
        LOG_IF_DEBUG("ringbuf result callback. value: " << value << " mapPath: "
                                                        << mapPath);
      }
    }
    now = std::chrono::steady_clock::now();
  }
  LOG_IF_DEBUG("finished polling for mapPath: " << mapPath);
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
    LOG(ERROR) << "Failed to parse uprobestats config: " << argv[1];
    return 1;
  }
  auto resolvedTask = config_resolver::resolveSingleTask(config.value());
  if (!resolvedTask.has_value()) {
    LOG(ERROR) << "Failed to parse task";
    return 1;
  }

  LOG_IF_DEBUG("Found task config: " << resolvedTask.value());
  std::set<std::string> mapPaths;
  auto resolvedProbeConfigs =
      config_resolver::resolveProbes(resolvedTask.value().taskConfig);
  if (!resolvedProbeConfigs.has_value()) {
    LOG(ERROR) << "Failed to resolve a probe config from task";
    return 1;
  }
  for (auto &resolvedProbe : resolvedProbeConfigs.value()) {
    LOG_IF_DEBUG("Opening bpf perf event from probe: " << resolvedProbe);
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
    LOG_IF_DEBUG(
        "Starting thread to collect results from mapPath: " << mapPath);
    threads.emplace_back(doPoll, poll_args);
  }
  for (auto &thread : threads) {
    thread.join();
  }

  LOG_IF_DEBUG("done.");

  return 0;
}
