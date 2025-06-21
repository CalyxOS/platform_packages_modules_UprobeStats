/*
 * Copyright 2025 The Android Open Source Project
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

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

#define MAX_STRING_LENGTH 64

void recordString(void *jstring, unsigned int max_length, char *dest) {
  // Assumes the following memory layout of a Java String object:
  // byte offset 8-11: count (this is the length of the string * 2)
  // byte offset 12-15: hash_code
  // byte offset 16 and beyond: string content
  __u32 count;
  bpf_probe_read_user(&count, sizeof(count), jstring + 8);
  count /= 2;
  bpf_probe_read_user_str(dest, max_length < count + 1 ? max_length : count + 1,
                          jstring + 16);
}

struct BinderTransaction {
  int calling_uid;
};

const int kBinderDescriptorOffset = 8;
const char kTargetInterfaceDescriptor[MAX_STRING_LENGTH] =
    "android.app.IActivityTaskManager";
const int kTargetCode = 1;  // IActivityTaskManager.startActivity

DEFINE_BPF_RINGBUF_EXT(output_buf, struct BinderTransaction, 4096,
                       AID_UPROBESTATS, AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/activity_task_manager_startActivity", AID_UPROBESTATS, AID_UPROBESTATS,
                BPF_KPROBE11)
(struct pt_regs *ctx) {
  // probe startActivity (code=1) only
  if (ctx->regs[2] != kTargetCode) return 0;
  void *this_binder_ptr = (void *)ctx->regs[1];
  void *descriptor_ptr = NULL;
  char interface_descriptor[MAX_STRING_LENGTH] = {0};
  bpf_probe_read_user(&descriptor_ptr, 4,
                      this_binder_ptr + kBinderDescriptorOffset);
  recordString(descriptor_ptr, MAX_STRING_LENGTH, interface_descriptor);
  // probe IActivityTaskManager only
  if (strcmp(interface_descriptor, kTargetInterfaceDescriptor) != 0) return 0;

  struct BinderTransaction *output = bpf_output_buf_reserve();
  if (output == NULL) return 1;
  output->calling_uid = ctx->regs[6];
  bpf_output_buf_submit(output);
  return 0;
}

LICENSE("GPL");
