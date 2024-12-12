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

#include <gtest/gtest.h>

#include "Guardrail.h"

namespace android {
namespace uprobestats {

class GuardrailTest : public ::testing::Test {};

TEST_F(GuardrailTest, EverythingAllowedOnUserDebugAndEng) {
  ::uprobestats::protos::UprobestatsConfig config;
  config.add_tasks()->add_probe_configs()->set_method_signature(
      "void com.android.server.am.SomeClass.doWork()");
  EXPECT_TRUE(guardrail::isAllowed(config, "userdebug", false));
  EXPECT_TRUE(guardrail::isAllowed(config, "eng", false));

  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfig;
  probeConfig.set_fully_qualified_class_name("com.android.server.am.SomeClass");
  probeConfig.set_method_name("doWork");
  ::uprobestats::protos::UprobestatsConfig newConfig;
  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfig);
  EXPECT_TRUE(guardrail::isAllowed(newConfig, "userdebug", true));
  EXPECT_TRUE(guardrail::isAllowed(newConfig, "eng", true));
}

TEST_F(GuardrailTest, OomAdjusterAllowed) {
  ::uprobestats::protos::UprobestatsConfig config;
  config.add_tasks()->add_probe_configs()->set_method_signature(
      "void com.android.server.am.OomAdjuster.setUidTempAllowlistStateLSP(int, "
      "boolean)");
  config.add_tasks()->add_probe_configs()->set_method_signature(
      "void "
      "com.android.server.am.OomAdjuster$$ExternalSyntheticLambda0.accept(java."
      "lang.Object)");
  EXPECT_TRUE(guardrail::isAllowed(config, "user", false));
  EXPECT_TRUE(guardrail::isAllowed(config, "userdebug", false));
  EXPECT_TRUE(guardrail::isAllowed(config, "eng", false));

  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfig;
  probeConfig.set_fully_qualified_class_name(
      "com.android.server.am.OomAdjuster");
  probeConfig.set_method_name("setUidTempAllowlistStateLSP");
  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfigTwo;
  probeConfigTwo.set_fully_qualified_class_name(
      "com.android.server.am.OomAdjuster$$ExternalSyntheticLambda0");
  probeConfigTwo.set_method_name("accept");
  ::uprobestats::protos::UprobestatsConfig newConfig;
  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfig);
  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfigTwo);
  EXPECT_TRUE(guardrail::isAllowed(newConfig, "user", true));
  EXPECT_TRUE(guardrail::isAllowed(newConfig, "userdebug", true));
  EXPECT_TRUE(guardrail::isAllowed(newConfig, "eng", true));
}

TEST_F(GuardrailTest, UpdateDeviceIdleTempAllowlistAllowed) {
  ::uprobestats::protos::UprobestatsConfig config;
  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig *probeConfig =
      config.add_tasks()->add_probe_configs();
  probeConfig->set_fully_qualified_class_name(
      "com.android.server.am.ActivityManagerService$LocalService");
  probeConfig->set_method_name("updateDeviceIdleTempAllowlist");
  EXPECT_TRUE(guardrail::isAllowed(config, "user", true));
  EXPECT_TRUE(guardrail::isAllowed(config, "userdebug", true));
  EXPECT_TRUE(guardrail::isAllowed(config, "eng", true));
}

TEST_F(GuardrailTest, DisallowOomAdjusterWithSuffix) {
  ::uprobestats::protos::UprobestatsConfig config;
  config.add_tasks()->add_probe_configs()->set_method_signature(
      "void com.android.server.am.OomAdjusterWithSomeSuffix.doWork()");
  EXPECT_FALSE(guardrail::isAllowed(config, "user", false));

  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfig;
  probeConfig.set_fully_qualified_class_name(
      "com.android.server.am.OomAdjusterWithSomeSuffix");
  probeConfig.set_method_name("doWork");
  ::uprobestats::protos::UprobestatsConfig newConfig;
  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfig);
  EXPECT_FALSE(guardrail::isAllowed(newConfig, "user", true));
}

TEST_F(GuardrailTest, DisallowedMethodInSecondTask) {
  ::uprobestats::protos::UprobestatsConfig config;
  config.add_tasks()->add_probe_configs()->set_method_signature(
      "void com.android.server.am.OomAdjuster.setUidTempAllowlistStateLSP(int, "
      "boolean)");
  config.add_tasks()->add_probe_configs()->set_method_signature(
      "void com.android.server.am.disallowedClass.doWork()");
  EXPECT_FALSE(guardrail::isAllowed(config, "user", false));

  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfig;
  probeConfig.set_fully_qualified_class_name(
      "com.android.server.am.OomAdjuster");
  probeConfig.set_method_name("setUidTempAllowlistStateLSP");
  ::uprobestats::protos::UprobestatsConfig::Task::ProbeConfig probeConfigTwo;
  probeConfigTwo.set_fully_qualified_class_name(
      "com.android.server.am.disallowedClass");
  probeConfigTwo.set_method_name("doWork");
  ::uprobestats::protos::UprobestatsConfig newConfig;
  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfig);
  newConfig.add_tasks()->add_probe_configs()->CopyFrom(probeConfigTwo);
  EXPECT_FALSE(guardrail::isAllowed(newConfig, "user", true));
}

} // namespace uprobestats
} // namespace android
