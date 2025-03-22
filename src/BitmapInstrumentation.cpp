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

#define LOG_TAG "uprobestats"

#include "BitmapInstrumentation.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <android/binder_process.h>
#include <android_uprobestats_mainline_flags.h>
#include <config.pb.h>
#include <iostream>
#include <stats_event.h>
#include <stdio.h>
#include <string>
#include <thread>

#include "Bpf.h"
#include "ConfigResolver.h"
#include "DebugLog.h"
#include "FlagSelector.h"
#include "Guardrail.h"
#include "statslog_uprobestats.h"

namespace android {
namespace uprobestats {
namespace bitmap_instrumentation {

using namespace android::uprobestats;

const std::string kBitmapAllocationMap = std::string("BitmapAllocation_output");

bool canHandleConfig(
    const ::uprobestats::protos::UprobestatsConfig::Task &taskConfig) {
  return taskConfig.bpf_maps_size() > 0 &&
         taskConfig.bpf_maps(0).find(kBitmapAllocationMap) != std::string::npos;
}

void startReadBitmapBpfOutput(
    const ::uprobestats::protos::UprobestatsConfig::Task &taskConfig) {

  auto mapPath = taskConfig.bpf_maps(0);
  auto durationSeconds = taskConfig.duration_seconds();
  auto duration = std::chrono::seconds(durationSeconds);
  auto startTime = std::chrono::steady_clock::now();
  auto now = startTime;
  while (now - startTime < duration) {
    auto remaining = duration - (std::chrono::steady_clock::now() - startTime);
    auto timeoutMs = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(remaining)
            .count());

    LOG_IF_DEBUG("Polling for Bitmap result");
    auto result = bpf::pollRingBuf<bpf::BitmapCreation>(mapPath, timeoutMs);
    for (auto value : result) {
      LOG_IF_DEBUG("Bitmap result:"
                   << " width: " << value.width << " height: " << value.height
                   << " storage type: " << value.pixel_storage_type);
      int atom_id = 1039;
      // TODO(b/400457896) log the actual uid.
      const int32_t DUMMY_UID = 0;
      stats_write(android::uprobestats::ANDROID_GRAPHICS_BITMAP_ALLOCATED,
                  DUMMY_UID, (int32_t)value.width, (int32_t)value.height);
    }
    now = std::chrono::steady_clock::now();
  }
  LOG_IF_DEBUG("finished polling for mapPath: " << mapPath);
}

} // namespace bitmap_instrumentation
} // namespace uprobestats
} // namespace android
