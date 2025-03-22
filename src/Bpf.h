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
                     const std::string &bpfProgramPath);

// TODO: share this struct with bpf
struct CallResult {
  unsigned long pc;
  unsigned long regs[10];
};

struct CallTimestamp {
  unsigned int event;
  unsigned long timestampNs;
};

struct SetUidTempAllowlistStateRecord {
  __u64 uid;
  bool onAllowlist;
};

struct UpdateDeviceIdleTempAllowlistRecord {
  int changing_uid;
  bool adding;
  long duration_ms;
  int type;
  int reason_code;
  char reason[256];
  int calling_uid;
};

#pragma pack(push, 1) // Pack structs with 1-byte boundary
struct WmBoundUid {
  __u64 client_uid;
  char client_package_name[64];
  unsigned long bind_flags;
  bool initialized;
};

struct ComponentEnabledSetting {
  char package_name[64];
  char class_name[64];
  int new_state;
  char calling_package_name[64];
  bool initialized;
};

struct MalwareSignal {
  struct WmBoundUid wm_bound_uid;
  struct ComponentEnabledSetting component_enabled_setting;
};
#pragma pack(pop)

struct ProcessChange {
  int pid;
  int uid;
  char process_name[256];
};

struct BitmapCreation {
  __u32 width;
  __u32 height;
  __u32 pixel_storage_type;
};

template <typename T>
std::vector<T> pollRingBuf(const std::string &mapPath, int timeoutMs);

} // namespace bpf
} // namespace uprobestats
} // namespace android
