import argparse
import subprocess
import sys
import time

kwargs = {
    'text': True,
    'shell': True,
    'capture_output': True,
    'check': True,
}


def get_offset():
  print('fetching offset')
  oatdump_cmd = (
      "adb shell 'oatdump"
      ' --oat-file=/system/framework/arm64/boot-framework.oat --method-filter=i'
      ' --class-filter=Slog | grep -A 1000 "Slog.i(.*dex_method" | grep "CODE:'
      ' ("\' | head -n 1 | cut -d = -f 2 | cut "-d " -f 1'
  )
  offset = subprocess.run(oatdump_cmd, **kwargs).stdout.splitlines()[0].strip()
  offset = int(offset, 0) + 4096
  return offset


def push_config():
  offset = get_offset()
  print('creating config-slog')
  config_cmd = (
      "adb shell 'echo /system/framework/arm64/boot-framework.oat %d >"
      " /data/misc/uprobestats-configs/config-slog'" % offset
  )
  subprocess.run(config_cmd, **kwargs)


def clear_logcat():
  print('clearing logcat')
  subprocess.run('adb logcat -c', **kwargs)


def start_uprobestats():
  print('starting uprobestats')
  subprocess.run(
      'adb shell setprop uprobestats.start_with_config config-slog', **kwargs
  )


def get_ring_buffer():
  print('generating log messages and fetching ring buffer size')
  subprocess.run('adb shell killall com.google.android.apps.photos', shell=True)
  time.sleep(2)
  subprocess.run(
      'adb shell monkey -p com.google.android.apps.photos -c'
      ' android.intent.category.LAUNCHER 1',
      **kwargs,
  )
  time.sleep(10)
  ring_buffer_size = (
      subprocess.run(
          'adb logcat -d | grep "uprobestats: ring buffer size"', **kwargs
      )
      .stdout.splitlines()[0]
      .split(':')[4]
      .strip()
  )

  print(f'ring buffer size: {ring_buffer_size}')
  return int(ring_buffer_size, 0)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(
      'Runs uprobestats over adb and checks if things are working'
  )
  parser.add_argument(
      '-i',
      '--iterations',
      type=int,
      default=0,
      help='Try n times to get a ring buffer > 0',
  )
  args = parser.parse_args()
  push_config()
  if args.iterations == 0:
    clear_logcat()
    start_uprobestats()
    get_ring_buffer()
    sys.exit(0)

  for _ in range(args.iterations):
    clear_logcat()
    start_uprobestats()
    ring_buf = get_ring_buffer()
    if ring_buf > 0:
      sys.exit(0)

  raise SystemExit('Never found a ring buffer greater than zero')
