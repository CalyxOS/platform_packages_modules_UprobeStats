/*
 * Copyright 2023 The Android Open Source Project
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

// TODO: import this struct from generic header, access registers via generic
// function
struct pt_regs {
  unsigned long regs[16];
  unsigned long pc;
  unsigned long pr;
  unsigned long sr;
  unsigned long gbr;
  unsigned long mach;
  unsigned long macl;
  long tra;
};

// TODO: share this struct between bpf and uprobestats
struct CallResult {
  unsigned long pc;
  unsigned long regs[10];
};

DEFINE_BPF_RINGBUF_EXT(output_buf, struct CallResult, 4096, AID_UPROBESTATS,
                       AID_UPROBESTATS, 0600, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG,
                       LOAD_ON_USER, LOAD_ON_USERDEBUG);

DEFINE_BPF_PROG("uprobe/call", AID_UPROBESTATS, AID_UPROBESTATS, BPF_KPROBE2)
(struct pt_regs *ctx) {
  struct CallResult result;
  // for whatever reason, reading past register 10 causes bpf verifier to fail
  for (int i = 0; i < 11; i++) {
    result.regs[i] = ctx->regs[i];
  }
  result.pc = ctx->pc;
  struct CallResult *output = bpf_output_buf_reserve();
  if (output == NULL)
    return 1;
  (*output) = result;
  bpf_output_buf_submit(output);
  return 0;
}

LICENSE("GPL");
