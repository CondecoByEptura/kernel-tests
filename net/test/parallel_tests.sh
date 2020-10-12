#!/bin/sh

# Runs many iterations of run_net_test.sh in parallel processes, for the
# purposes of finding flaky tests.

if ! [[ $1 =~ ^[0-9]+$ ]] || ! [[ $2 =~ ^[0-9]+$ ]] || [ -z "$3" ]; then
  echo "Usage: $0 <workers> <runs_per_worker> <test>" >&2
  exit 1
fi

# A function run by every worker. Runs the tests <runs_per_worker> times.
function runtests() {
  local worker=$1
  local runs=$2
  local test=$3
  local j=0
  while ((j < runs)); do
    local outfile=$RESULTSDIR/results.$worker.$j
    $DIR/run_net_test.sh --builder --nobuild $test > /dev/null 2> $outfile

    # We can't check for exit status because sometimes UML exits with nonzero
    # status even though the tests passed. Grep the logs for errors instead.
    # This matches what the error parsing below does, except in the case of
    # errors where the test doesn't fail (e.g., syntax errors).
    if egrep -q "^ERROR: " $outfile; then
      echo -n "E" >&2
    elif egrep -q "^FAIL: " $outfile; then
      echo -n "F" >&2
    elif egrep -q "^Ran [0-9]+ tests in " $outfile; then
      echo -n "." >&2
    else
      echo -n "e" >&2
    fi

    j=$((j + 1))
  done
}

WORKERS=$1
RUNS=$2
TEST=$3
DIR=$(dirname $0)
RESULTSDIR=$(mktemp --tmpdir -d net_test.parallel.XXXXXX)
[ -z $RESULTSDIR ] && exit 1

test_file=$DIR/$TEST
if [[ ! -x $test_file ]]; then
  echo "test file '${test_file}' does not exist"
  exit 1
fi

echo "Building kernel..." >&2
$DIR/run_net_test.sh --norun || exit 1

echo "Running $WORKERS worker(s) with $RUNS test run(s) each..." >&2

# Start all the workers.
worker=0
while ((worker < WORKERS)); do
  runtests $worker $RUNS $TEST &
  worker=$((worker + 1))
done
wait

echo

# Output the results.
egrep -h "^ERROR:|^FAIL:|0 failed tests|giving up" $RESULTSDIR/results.* | \
    sort | uniq -c | sort -rn >&2

# If there were any failures, leave the results around for examination.
if egrep -q "^ERROR:|^FAIL:" $RESULTSDIR/results.*; then
  echo "Failures occurred, leaving results in $RESULTSDIR" >&2
else
  rm -rf $RESULTSDIR
fi
