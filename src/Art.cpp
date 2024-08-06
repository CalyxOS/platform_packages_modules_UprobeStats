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

#include <json/json.h>
#include <string>

namespace android {
namespace uprobestats {
namespace art {

const int PAGE_OFFSET = 16384;

// Uses the oatdump binary to retrieve the offset for a given method
int getMethodOffsetFromOatdump(std::string oatFile,
                               std::string methodSignature) {
  // call oatdump and collect stdout
  auto command = std::string("oatdump --oat-file=") + oatFile +
                 std::string(" --dump-method-and-offset-as-json");
  FILE *pipe = popen(command.c_str(), "r");
  char buffer[256];
  std::string result = "";
  while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
    result += buffer;
  }
  pclose(pipe);

  // find the first json blob with a method matching the provided signature
  std::stringstream ss(result);
  std::string line;
  Json::Reader reader;
  while (std::getline(ss, line)) {
    Json::Value entry;
    bool success = reader.parse(line, entry);
    if (success) {
      auto foundMethodSignature = entry["method"].asString();
      if (foundMethodSignature == methodSignature) {
        auto hexString = entry["offset"].asString();
        int offset;
        std::istringstream stream(hexString);
        stream >> std::hex >> offset;
        if (offset == 0) {
          return 0;
        }
        return offset + PAGE_OFFSET;
      }
    }
  }

  return 0;
}

} // namespace art
} // namespace uprobestats
} // namespace android