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

#include "DynamicInstrumentationManager.h"
#include "DebugLog.h"
#include <android-base/logging.h>
#include <android-base/scopeguard.h>
#include <assert.h>
#include <dlfcn.h>
#include <log/log.h>
#include <optional>
#include <string>
#include <vector>

namespace android::uprobestats::dynamic_instrumentation_manager {

struct ADynamicInstrumentationManager_MethodDescriptor;
typedef struct ADynamicInstrumentationManager_MethodDescriptor
    ADynamicInstrumentationManager_MethodDescriptor;

struct ADynamicInstrumentationManager_TargetProcess;
typedef struct ADynamicInstrumentationManager_TargetProcess
    ADynamicInstrumentationManager_TargetProcess;

struct ADynamicInstrumentationManager_ExecutableMethodFileOffsets;
typedef struct ADynamicInstrumentationManager_ExecutableMethodFileOffsets
    ADynamicInstrumentationManager_ExecutableMethodFileOffsets;

typedef ADynamicInstrumentationManager_TargetProcess *(
    *ADynamicInstrumentationManager_TargetProcess_create)(
    uid_t uid, pid_t pid, const char *processName);
typedef void (*ADynamicInstrumentationManager_TargetProcess_destroy)(
    const ADynamicInstrumentationManager_TargetProcess *instance);

typedef ADynamicInstrumentationManager_MethodDescriptor *(
    *ADynamicInstrumentationManager_MethodDescriptor_create)(
    const char *fullyQualifiedClassName, const char *methodName,
    const char *fullyQualifiedParameters[], unsigned int numParameters);
typedef void (*ADynamicInstrumentationManager_MethodDescriptor_destroy)(
    const ADynamicInstrumentationManager_MethodDescriptor *instance);

typedef const char *(
    *ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath)(
    const ADynamicInstrumentationManager_ExecutableMethodFileOffsets *instance);
typedef unsigned long (
    *ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerOffset)(
    const ADynamicInstrumentationManager_ExecutableMethodFileOffsets *instance);
typedef unsigned long (
    *ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getMethodOffset)(
    const ADynamicInstrumentationManager_ExecutableMethodFileOffsets *instance);
typedef void (
    *ADynamicInstrumentationManager_ExecutableMethodFileOffsets_destroy)(
    const ADynamicInstrumentationManager_ExecutableMethodFileOffsets *instance);

typedef int32_t (
    *ADynamicInstrumentationManager_getExecutableMethodFileOffsets)(
    const ADynamicInstrumentationManager_TargetProcess &targetProcess,
    const ADynamicInstrumentationManager_MethodDescriptor &methodDescriptor,
    const ADynamicInstrumentationManager_ExecutableMethodFileOffsets **out);

const char kLibandroidPath[] = "libandroid.so";

template <typename T>
void getLibFunction(void *handle, const char *identifier, T *out) {
  auto result = reinterpret_cast<T>(dlsym(handle, identifier));
  if (!result) {
    ALOGE("dlsym error: %s %s %s", __func__, dlerror(), identifier);
    assert(result);
  }
  *out = result;
}

std::optional<ExecutableMethodFileOffsets>
getExecutableMethodFileOffsets(int pid, int uid, std::string &processName,
                               std::string &fqcn, std::string &methodName,
                               std::vector<std::string> &fqParameters) {
  void *handle = dlopen(kLibandroidPath, RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    ALOGE("dlopen error: %s %s", __func__, dlerror());
    return {};
  }

  ADynamicInstrumentationManager_TargetProcess_create targetProcess_create;
  getLibFunction(handle, "ADynamicInstrumentationManager_TargetProcess_create",
                 &targetProcess_create);
  ADynamicInstrumentationManager_TargetProcess_destroy targetProcess_destroy;
  getLibFunction(handle, "ADynamicInstrumentationManager_TargetProcess_destroy",
                 &targetProcess_destroy);
  ADynamicInstrumentationManager_MethodDescriptor_create
      methodDescriptor_create;
  getLibFunction(handle,
                 "ADynamicInstrumentationManager_MethodDescriptor_create",
                 &methodDescriptor_create);
  ADynamicInstrumentationManager_MethodDescriptor_destroy
      methodDescriptor_destroy;
  getLibFunction(handle,
                 "ADynamicInstrumentationManager_MethodDescriptor_destroy",
                 &methodDescriptor_destroy);
  ADynamicInstrumentationManager_getExecutableMethodFileOffsets
      getExecutableMethodFileOffsets;
  getLibFunction(
      handle, "ADynamicInstrumentationManager_getExecutableMethodFileOffsets",
      &getExecutableMethodFileOffsets);
  ADynamicInstrumentationManager_ExecutableMethodFileOffsets_destroy
      executableMethodFileOffsets_destroy;
  getLibFunction(
      handle,
      "ADynamicInstrumentationManager_ExecutableMethodFileOffsets_destroy",
      &executableMethodFileOffsets_destroy);
  ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerPath
      getContainerPath;
  getLibFunction(handle,
                 "ADynamicInstrumentationManager_ExecutableMethodFileOffsets_"
                 "getContainerPath",
                 &getContainerPath);
  ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getContainerOffset
      getContainerOffset;
  getLibFunction(handle,
                 "ADynamicInstrumentationManager_ExecutableMethodFileOffsets_"
                 "getContainerOffset",
                 &getContainerOffset);
  ADynamicInstrumentationManager_ExecutableMethodFileOffsets_getMethodOffset
      getMethodOffset;
  getLibFunction(handle,
                 "ADynamicInstrumentationManager_ExecutableMethodFileOffsets_"
                 "getMethodOffset",
                 &getMethodOffset);

  const ADynamicInstrumentationManager_TargetProcess *targetProcess =
      targetProcess_create(uid, pid, processName.c_str());

  std::vector<const char *> fqpVec;
  for (size_t i = 0; i < fqParameters.size(); ++i) {
    fqpVec.push_back(fqParameters[i].c_str());
  }
  const ADynamicInstrumentationManager_MethodDescriptor *methodDescriptor =
      methodDescriptor_create(fqcn.c_str(), methodName.c_str(), fqpVec.data(),
                              fqParameters.size());

  const ADynamicInstrumentationManager_ExecutableMethodFileOffsets *offsets =
      nullptr;
  int32_t result = getExecutableMethodFileOffsets(*targetProcess,
                                                  *methodDescriptor, &offsets);

  targetProcess_destroy(targetProcess);
  methodDescriptor_destroy(methodDescriptor);

  if (result != 0) {
    LOG(ERROR) << "error calling getExecutableMethodFileOffsets. result: "
               << result;
  }

  if (offsets == nullptr) {
    LOG(ERROR) << "could not find offset for " << methodName;
    return {};
  }

  const char *cp = getContainerPath(offsets);
  std::string containerPath(cp);
  uint64_t containerOffset = getContainerOffset(offsets);
  uint64_t methodOffset = getMethodOffset(offsets);

  executableMethodFileOffsets_destroy(offsets);

  ExecutableMethodFileOffsets executableMethodFileOffsets;
  executableMethodFileOffsets.containerPath = containerPath;
  executableMethodFileOffsets.containerOffset = containerOffset;
  executableMethodFileOffsets.methodOffset = methodOffset;
  return executableMethodFileOffsets;
}
} // namespace android::uprobestats::dynamic_instrumentation_manager
