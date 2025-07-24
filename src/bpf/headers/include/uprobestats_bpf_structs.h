/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <sys/types.h>

#define MAX_STRING_LENGTH 128

__BEGIN_DECLS

// TODO(b/408763304): use libbpf instead of redefining pt_regs, which is defined
// by the kernel and architecture specific.
struct pt_regs {
  unsigned long regs[31];
  unsigned long sp;
  unsigned long pc;
  unsigned long pr;
  unsigned long sr;
  unsigned long gbr;
  unsigned long mach;
  unsigned long macl;
  long tra;
};

struct CallTimestamp {
  unsigned int event;
  unsigned long timestampNs;
};

struct CallResult {
  unsigned long pc;
  unsigned long regs[10];
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

struct BindServiceLocked {
  char intent_action[MAX_STRING_LENGTH];
  char intent_package[MAX_STRING_LENGTH];
  char intent_component_name_package[MAX_STRING_LENGTH];
  char intent_component_name_class[MAX_STRING_LENGTH];
  long bind_flags;
  char calling_package[MAX_STRING_LENGTH];
};

struct ComponentEnabledSetting {
  char package_name[MAX_STRING_LENGTH];
  char class_name[MAX_STRING_LENGTH];
  int new_state;
  char calling_package_name[MAX_STRING_LENGTH];
};

struct ProcessChange {
  int pid;
  int uid;
  char process_name[256];
};

struct BitmapAllocation {
  __u32 type;
  __u32 width;
  __u32 height;
  __u32 pixel_storage_type;
  __u32 bitmap_size;
  void* native_ptr;
  char activity_name[128];
};

struct BinderTransaction {
  int calling_uid;
};

__END_DECLS
