import argparse
import os
import subprocess
import sys
import time
import config_pb2
import google.protobuf.text_format as text_format

kwargs = {
    'text': True,
    'shell': True,
    'capture_output': True,
    'check': True,
}


def get_current_dir():
  """returns the current dir, relative to the script dir."""
  current_dir = os.path.dirname(os.path.realpath(__file__))
  return current_dir


textproto_file = f'{get_current_dir()}/test_slog.textproto'
pb_file = f'{get_current_dir()}/test_slog.pb'


def create_config_proto():
  textproto = open(textproto_file, 'r')
  message = text_format.Parse(textproto.read(), config_pb2.UprobestatsConfig())
  textproto.close()

  pb = open(pb_file, 'wb')
  pb.write(message.SerializeToString())
  pb.flush()
  pb.close()


def push_config():
  print('creating config-slog')
  config_cmd = (
      f'adb push {pb_file} /data/misc/uprobestats-configs/config-slog.pb'
  )
  subprocess.run(config_cmd, **kwargs)


def clear_logcat():
  print('clearing logcat')
  subprocess.run('adb logcat -c', **kwargs)


def start_uprobestats():
  print('starting uprobestats')
  subprocess.run(
      'adb shell setprop uprobestats.start_with_config config-slog.pb', **kwargs
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
  create_config_proto()
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
