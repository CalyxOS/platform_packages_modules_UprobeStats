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

#pragma once

namespace android {
namespace uprobestats {
namespace bpf {

int bpfPerfEventOpen(const char *filename, int offset, int pid,
                     const char *bpfProgramPath);

std::vector<int32_t> consumeRingBuf(const char *mapPath);

// TODO: share this struct with bpf
struct CallResult {
  unsigned long pc;
  unsigned long regs[10];
};

struct CallTimestamp {
  unsigned int event;
  unsigned long timestampNs;
};

template <typename T>
std::vector<T> pollRingBuf(const char *mapPath, int timeoutMs);

void printRingBuf(const char *mapPath);

} // namespace bpf
} // namespace uprobestats
} // namespace android
