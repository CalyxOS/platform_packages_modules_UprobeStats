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

#pragma once

namespace android {
namespace uprobestats {
namespace config_resolver {

struct BpfPerfEventConfig {
  std::string filename;
  int offset;
  int pid;
  std::string bpfProgramPath;
  std::string bpfMapPath;
};

std::ostream &operator<<(std::ostream &os, const BpfPerfEventConfig &c);

// Parses config and returns a list of arguments for
// `android::uprobestats::bpfPerfEventOpen`
std::optional<std::vector<BpfPerfEventConfig>>
getBpfPerfEventConfigs(std::string configFilePath);

} // namespace config_resolver
} // namespace uprobestats
} // namespace android
