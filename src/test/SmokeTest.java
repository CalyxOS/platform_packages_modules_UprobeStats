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

package test;

import static com.google.common.truth.Truth.assertThat;

import android.cts.statsdatom.lib.AtomTestUtils;
import android.cts.statsdatom.lib.ConfigUtils;
import android.cts.statsdatom.lib.DeviceUtils;
import android.cts.statsdatom.lib.ReportUtils;

import com.android.internal.os.StatsdConfigProto;
import com.android.os.StatsLog;
import com.android.os.uprobestats.TestUprobeStatsAtomReported;
import com.android.os.uprobestats.UprobestatsExtensionAtoms;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.testtype.DeviceTestCase;
import com.android.tradefed.util.RunUtil;

import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.TextFormat;

import uprobestats.protos.Config.UprobestatsConfig;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Scanner;

public class SmokeTest extends DeviceTestCase {

    private static final String BATTERY_STATS_CONFIG = "test_bss_setBatteryState.textproto";
    private static final String CONFIG_NAME = "test";
    private static final String CMD_SETPROP_UPROBESTATS = "setprop uprobestats.start_with_config ";
    private static final String CONFIG_DIR = "/data/misc/uprobestats-configs/";

    @Override
    protected void setUp() throws Exception {
        ConfigUtils.removeConfig(getDevice());
        ReportUtils.clearReports(getDevice());
        getDevice().deleteFile(CONFIG_DIR + CONFIG_NAME);
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
    }

    public void testBatteryStats() throws Exception {
        // 1. Parse config from resources
        String textProto =
                new Scanner(this.getClass().getResourceAsStream(BATTERY_STATS_CONFIG))
                        .useDelimiter("\\A")
                        .next();
        UprobestatsConfig.Builder builder = UprobestatsConfig.newBuilder();
        TextFormat.getParser().merge(textProto, builder);
        UprobestatsConfig config = builder.build();

        // 2. Write config to a file and drop it on the device
        File tmp = File.createTempFile("uprobestats", CONFIG_NAME);
        assertTrue(tmp.setWritable(true));
        Files.write(tmp.toPath(), config.toByteArray());
        ITestDevice device = getDevice();
        assertTrue(getDevice().enableAdbRoot());
        assertTrue(getDevice().pushFile(tmp, CONFIG_DIR + CONFIG_NAME));

        // 3. Configure StatsD
        ExtensionRegistry registry = ExtensionRegistry.newInstance();
        UprobestatsExtensionAtoms.registerAllExtensions(registry);
        StatsdConfigProto.StatsdConfig.Builder configBuilder =
                ConfigUtils.createConfigBuilder("AID_UPROBESTATS");
        ConfigUtils.addEventMetric(
                configBuilder,
                UprobestatsExtensionAtoms.TEST_UPROBESTATS_ATOM_REPORTED_FIELD_NUMBER);
        ConfigUtils.uploadConfig(getDevice(), configBuilder);

        // 4. Start UprobeStats
        device.executeShellCommand(CMD_SETPROP_UPROBESTATS + CONFIG_NAME);
        // Allow UprobeStats time to attach probe
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        // 5. Set charging state, which should invoke BatteryStatsService#setBatteryState.
        // Assumptions:
        //   - uprobestats flag is enabled
        //   - userdebug build
        //   - said method is precompiled (specified in frameworks/base/services/art-profile)
        // If this test fails, check those assumptions first.
        DeviceUtils.setChargingState(getDevice(), 2);
        // Allow UprobeStats/StatsD time to collect metric
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        // 6. See if the atom made it
        List<StatsLog.EventMetricData> data =
                ReportUtils.getEventMetricDataList(getDevice(), registry);
        assertThat(data.size()).isEqualTo(1);
        TestUprobeStatsAtomReported reported =
                data.get(0)
                        .getAtom()
                        .getExtension(UprobestatsExtensionAtoms.testUprobestatsAtomReported);
        assertThat(reported.getFirstField()).isEqualTo(1);
        assertThat(reported.getSecondField()).isGreaterThan(0);
        assertThat(reported.getThirdField()).isEqualTo(0);
    }
}
