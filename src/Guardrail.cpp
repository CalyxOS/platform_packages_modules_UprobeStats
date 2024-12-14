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

#include <android-base/strings.h>
#include <config.pb.h>
#include <string>

namespace android {
namespace uprobestats {
namespace guardrail {

using std::string;

namespace {

constexpr std::array kAllowedMethodPrefixes = {
    "com.android.server.am.ActivityManagerService$LocalService."
    "updateDeviceIdleTempAllowlist",
    "com.android.server.am.CachedAppOptimizer",
    "com.android.server.am.OomAdjuster",
    "com.android.server.am.OomAdjusterModernImpl",
};

} // namespace

std::string getFullMethodName(
    const ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig
        &probeConfig,
    bool executabeMethodFileOffsetsApiEnabled) {
  if (executabeMethodFileOffsetsApiEnabled &&
      probeConfig.has_fully_qualified_class_name()) {
    return probeConfig.fully_qualified_class_name() + "." +
           probeConfig.method_name();
  }
  const string &methodSignature = probeConfig.method_signature();
  std::vector<string> components = android::base::Split(methodSignature, " ");
  if (components.size() < 2) {
    return "";
  }
  return components[1];
}

bool isAllowed(const ::uprobestats::protos::UprobestatsConfig &config,
               const string &buildType,
               bool executabeMethodFileOffsetsApiEnabled) {
  if (buildType != "user") {
    return true;
  }
  for (const auto &task : config.tasks()) {
    for (const auto &probeConfig : task.probe_configs()) {
      const string &fullMethodName =
          getFullMethodName(probeConfig, executabeMethodFileOffsetsApiEnabled);
      bool allowed = false;
      for (const std::string allowedPrefix : kAllowedMethodPrefixes) {
        if (android::base::StartsWith(fullMethodName, allowedPrefix + ".") ||
            android::base::StartsWith(fullMethodName, allowedPrefix + "$") ||
            fullMethodName == allowedPrefix) {
          allowed = true;
          break;
        }
      }
      if (!allowed) {
        return false;
      }
    }
  }
  return true;
}

} // namespace guardrail
} // namespace uprobestats
} // namespace android
