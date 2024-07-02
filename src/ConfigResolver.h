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

struct ResolvedProbe {
  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfig;
  std::string filename;
  int offset;
};

struct ResolvedTask {
  ::uprobestats::protos::UprobestatsConfig::Task taskConfig;
  int pid;
};

std::ostream &operator<<(std::ostream &os, const ResolvedTask &c);

std::ostream &operator<<(std::ostream &os, const ResolvedProbe &c);

std::optional<::uprobestats::protos::UprobestatsConfig>
readConfig(std::string configFilePath);

std::optional<ResolvedTask>
resolveSingleTask(::uprobestats::protos::UprobestatsConfig config);

std::optional<std::vector<ResolvedProbe>>
resolveProbes(::uprobestats::protos::UprobestatsConfig::Task taskConfig);

} // namespace config_resolver
} // namespace uprobestats
} // namespace android
