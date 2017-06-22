#!/usr/bin/env python3.4
#
#   Copyright 2016 - The Android Open Source Project
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
import logging
import os
import subprocess
import sys

# Forked from tools/test/connectivity/tools/yapf_checker.py

COMMIT_ID_ENV_KEY = 'PREUPLOAD_COMMIT'
REPO_PATH_KEY = 'REPO_PATH'
GIT_COMMAND = 'git diff-tree --no-commit-id --name-only -r %s'
YAPF_COMMAND = 'yapf --style=chromium -d %s'
YAPF_INPLACE_FORMAT = 'yapf --style=chromium -i %s'


def main(argv):
  if COMMIT_ID_ENV_KEY not in os.environ:
    logging.error('Missing commit id in environment.')
    exit(1)

  if REPO_PATH_KEY not in os.environ:
    logging.error('Missing repo path in environment.')
    exit(1)

  commit_id = os.environ[COMMIT_ID_ENV_KEY]
  full_git_command = GIT_COMMAND % commit_id

  list_files_proc = subprocess.Popen(
      full_git_command.split(),
      stdout=subprocess.PIPE,
      stderr=subprocess.DEVNULL)
  list_files_proc.wait()

  files = list_files_proc.stdout.read().decode('utf-8').splitlines()
  full_files = [os.path.abspath(f) for f in files if f.endswith('.py')]
  if not full_files:
    return

  files_param_string = ' '.join(full_files)

  yapf_command = (YAPF_COMMAND % files_param_string).split()
  yapf_proc = subprocess.Popen(
      yapf_command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
  yapf_proc.wait()

  result = yapf_proc.stdout.read().decode('utf-8')
  if result:
    logging.error('\n' + result)
    logging.error('INVALID FORMATTING. Consider running:\n\t' +
                  YAPF_INPLACE_FORMAT % files_param_string)
    exit(1)


if __name__ == '__main__':
  main(sys.argv[1:])
