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

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android_uprobestats_flags.h>
#include <android_uprobestats_mainline_flags.h>
#include <config.pb.h>
#include <json/json.h>

#include "Bpf.h"
#include "ConfigResolver.h"
#include "DebugLog.h"

namespace android {
namespace uprobestats {
namespace process {

using ::uprobestats::protos::
    UprobestatsConfig_Task_TargetProcessSelection_ANY_APP_PROCESS_ON_START;
using ::uprobestats::protos::
    UprobestatsConfig_Task_TargetProcessSelection_SPECIFIC_APP_PROCESS_ON_START;
using ::uprobestats::protos::
    UprobestatsConfig_Task_TargetProcessSelection_SPECIFIC_PROCESS_NAME;
using ::uprobestats::protos::
    UprobestatsConfig_Task_TargetProcessSelection_UNKNOWN;

int getPid(const std::string &processName) {
  for (const auto &entry : std::filesystem::directory_iterator("/proc")) {
    std::string cmdline;
    android::base::ReadFileToString(entry.path() / "cmdline", &cmdline);
    if (android::base::ReadFileToString(entry.path() / "cmdline", &cmdline) &&
        (cmdline == processName ||
         (cmdline.rfind(processName + '\0', 0) == 0))) {
      std::string pidStr =
          entry.path().string().substr(entry.path().string().rfind("/") + 1);
      int pid;
      if (!android::base::ParseInt(pidStr, &pid)) {
        return -1;
      }
      return pid;
    }
  }
  return -1;
}

// Waits until an app process starts. Returns false on timeout.
bool waitForAppStart(const std::string &processName, int timeoutSecs, int *pid,
                     int *uid) {
  ::uprobestats::protos::UprobestatsConfig::Task task;
  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig *probeConfig =
      task.add_probe_configs();
  probeConfig->set_bpf_name("prog_ProcessManagement_uprobe_make_active");
  probeConfig->set_fully_qualified_class_name(
      "com.android.server.am.ProcessRecord");
  probeConfig->set_method_name("makeActive");
  probeConfig->add_fully_qualified_parameters(
      "com.android.server.am.ApplicationThreadDeferred");
  probeConfig->add_fully_qualified_parameters(
      "com.android.server.am.ProcessStatsService");
  task.set_target_process_name("system_server");
  auto resolvedProbeConfigs = config_resolver::resolveProbes(task, 0, 0);
  if (!resolvedProbeConfigs.has_value()) {
    LOG(ERROR)
        << "Failed to resolve a probe config for ProcessRecord.makeActive";
    return false;
  }
  if (resolvedProbeConfigs.value().size() != 1) {
    LOG(ERROR) << "Expecting one resolved probe config for "
               << "ProcessRecord.makeActive but got: "
               << resolvedProbeConfigs.value().size();
    return false;
  }
  int systemServerPid = getPid("system_server");
  if (systemServerPid < 0) {
    LOG(ERROR) << "Failed to get pid of system_server";
    return false;
  }
  auto &resolvedProbe = resolvedProbeConfigs.value()[0];
  auto openResult = bpf::bpfPerfEventOpen(resolvedProbe.filename.c_str(),
                                          resolvedProbe.offset, systemServerPid,
                                          resolvedProbe.probeConfig.bpf_name());
  if (openResult != 0) {
    LOG(ERROR) << "Failed to open bpf " << resolvedProbe.probeConfig.bpf_name();
    return 1;
  }
  auto duration = std::chrono::seconds(timeoutSecs);
  auto startTime = std::chrono::steady_clock::now();
  auto now = startTime;
  while (now - startTime < duration) {
    auto remaining = duration - (std::chrono::steady_clock::now() - startTime);
    auto timeoutMs = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(remaining)
            .count());
    LOG_IF_DEBUG("Polling for ProcessList result");
    auto result = bpf::pollRingBuf<bpf::ProcessChange>(
        "map_ProcessManagement_process_change_output_buf", timeoutMs);
    if (result.size() > 0 &&
        (processName.empty() || processName == result[0].process_name) &&
        result[0].pid > 0) {
      *pid = result[0].pid;
      *uid = result[0].uid;
      return true;
    }
    now = std::chrono::steady_clock::now();
  }
  return false;
}

bool getPidUid(const ::uprobestats::protos::UprobestatsConfig::Task &task,
               int *pid, int *uid) {
  switch (task.target_process_selection()) {
  case UprobestatsConfig_Task_TargetProcessSelection_UNKNOWN:
  case UprobestatsConfig_Task_TargetProcessSelection_SPECIFIC_PROCESS_NAME: {
    auto process_name = task.target_process_name();
    *pid = getPid(process_name);
    if (*pid < 0) {
      LOG(ERROR) << "Unable to find pid of " << process_name;
      return false;
    }
    return true;
  } break;
  case UprobestatsConfig_Task_TargetProcessSelection_ANY_APP_PROCESS_ON_START:
    if (!android::uprobestats::mainline::flags::
            enable_bitmap_instrumentation()) {
      LOG(ERROR)
          << "TargetProcessSelection_ANY_APP_PROCESS_ON_START disabled by flag";
      return false;
    }
    return waitForAppStart("", task.duration_seconds(), pid, uid);
    break;
  case UprobestatsConfig_Task_TargetProcessSelection_SPECIFIC_APP_PROCESS_ON_START:
    if (!android::uprobestats::mainline::flags::
            enable_bitmap_instrumentation()) {
      LOG(ERROR) << "TargetProcessSelection_SPECIFIC_APP_PROCESS_ON_START "
                    "disabled by flag";
      return false;
    }
    return waitForAppStart(task.target_process_name(), task.duration_seconds(),
                           pid, uid);
    break;
  default:
    LOG(ERROR) << "Unsupported target_process_selection: "
               << task.target_process_selection();
    return false;
  }
}

} // namespace process
} // namespace uprobestats
} // namespace android
