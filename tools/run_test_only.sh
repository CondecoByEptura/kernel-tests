#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

#
# A simple script to run test with Tradefed.
#

KERNEL_TF_PREBUILT=prebuilts/tradefed/filegroups/tradefed/tradefed.sh
PLATFORM_TF_PREBUILT=tools/tradefederation/prebuilts/filegroups/tradefed/tradefed.sh
JDK_PATH=prebuilts/jdk/jdk11/linux-x86
PLATFORM_JDK_PATH=prebuilts/jdk/jdk21/linux-x86
DEFAULT_LOG_DIR=$PWD/out/test_logs/$(date +%Y%m%d_%H%M%S)
GCOV=false
FETCH_SCRIPT="fetch_artifact.sh"
TRADEFED=
TEST_ARGS=()
TEST_DIR=
TEST_NAMES=()

function adb_checker() {
    if ! which adb &> /dev/null; then
        echo -e "\n${RED}Adb not found!${END}"
    fi
}

function go_to_repo_root() {
    current_dir="$1"
    while [ ! -d ".repo" ] && [ "$current_dir" != "/" ]; do
        current_dir=$(dirname "$current_dir")  # Go up one directory
        cd "$current_dir"
    done
}

function print_info() {
    echo "${GREEN}$1${END}"
}

function print_warn() {
    echo "${YELLOW}$1${END}"
}

function print_error() {
    echo -e "${RED}$1${END}"
}

print_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "This script will run tests on an Android device."
    echo ""
    echo "Available options:"
    echo "  -s <serial_number>, --serial=<serial_number>"
    echo "                        The device serial number to run tests with."
    echo "  -td <test_dir>, --test-dir=<test_dir>"
    echo "                        The test artifact file name or directory path."
    echo "                        Can be a local file or directory or a remote file"
    echo "                        as ab://<branch>/<build_target>/<build_id>/<file_name>."
    echo "                        If not specified, it will use the tests in the local"
    echo "                        repo."
    echo "  -tl <test_log_dirR>, --test_log=<test_log_dir>"
    echo "                        The test log dir. Use default out/test_logs if not specified."
    echo "  -ta <extra_arg>, --extra-arg=<extra_arg>"
    echo "                        Additional tradefed command arg. Can be repeated."
    echo "  -t <test_name>, --test=<test_name>  The test name. Can be repeated."
    echo "                        If test is not specified, no tests will be run."
    echo "  -tf <tradefed_binary_path>, --tradefed-bin=<tradefed_binary_path>"
    echo "                        The alternative tradefed binary to run test with."
    echo "  --gcov                Collect coverage data from the test result"
    echo "  -h, --help            Display this help message and exit"
    echo ""
    echo "Examples:"
    echo "$0 -s 127.0.0.1:33847 -t selftests"
    echo "$0 -s 1C141FDEE003FH -t selftests:kselftest_binderfs_binderfs_test"
    echo "$0 -s 127.0.0.1:33847 -t CtsAccessibilityTestCases -t CtsAccountManagerTestCases"
    echo "$0 -s 127.0.0.1:33847 -t CtsAccessibilityTestCases -t CtsAccountManagerTestCases \
-td ab://aosp-main/test_suites_x86_64-trunk_staging/latest/android-cts.zip"
    echo "$0 -s 1C141FDEE003FH -t CtsAccessibilityTestCases -t CtsAccountManagerTestCases \
-td ab://git_main/test_suites_arm64-trunk_staging/latest/android-cts.zip"
    echo ""
    exit 0
}

while test $# -gt 0; do
    case "$1" in
        -h|--help)
            print_help
            ;;
        -s)
            shift
            if test $# -gt 0; then
                SERIAL_NUMBER=$1
            else
                echo "device serial is not specified"
                exit 1
            fi
            shift
            ;;
        --serial*)
            SERIAL_NUMBER=$(echo $1 | sed -e "s/^[^=]*=//g")
            shift
            ;;
        -tl)
            shift
            if test $# -gt 0; then
                LOG_DIR=$1
            else
                echo "test log directory is not specified"
                exit 1
            fi
            shift
            ;;
        --test-log*)
            LOG_DIR=$(echo $1 | sed -e "s/^[^=]*=//g")
            shift
            ;;
        -td)
            shift
            if test $# -gt 0; then
                TEST_DIR=$1
            else
                echo "test directory is not specified"
                exit 1
            fi
            shift
            ;;
        --test-dir*)
            TEST_DIR=$(echo $1 | sed -e "s/^[^=]*=//g")
            shift
            ;;
        -ta)
            shift
            if test $# -gt 0; then
                TEST_ARGS+=$1
            else
                echo "test arg is not specified"
                exit 1
            fi
            shift
            ;;
        --test-arg*)
            TEST_ARGS+=$(echo $1 | sed -e "s/^[^=]*=//g")
            shift
            ;;
        -t)
            shift
            if test $# -gt 0; then
                TEST_NAMES+=$1
            else
                echo "test name is not specified"
                exit 1
            fi
            shift
            ;;
        --test*)
            TEST_NAMES+=$1
            shift
            ;;
        -tf)
            shift
            if test $# -gt 0; then
                TRADEFED=$1
            else
                echo "tradefed binary is not specified"
                exit 1
            fi
            shift
            ;;
        --tradefed-bin*)
            TRADEFED=$(echo $1 | sed -e "s/^[^=]*=//g")
            shift
            ;;
        --gcov)
            GCOV=true
            shift
            ;;
        *)
            ;;
    esac
done

if [ -z "$SERIAL_NUMBER" ]; then
    print_error "Device serial is not provided with flag -s <serial_number>."
    exit 1
fi

# Ensure TEST_NAMES is provided
if [ -z "$TEST_NAMES" ]; then
    print_error "No test is specified with flag -t <test_name>."
    exit 1
fi

FULL_COMMAND_PATH=$(dirname "$PWD/$0")
REPO_LIST_OUT=$(repo list 2>&1)
if [[ "$REPO_LIST_OUT" == "error"* ]]; then
    print_error "Current path $PWD is not in an Android repo. Change path to repo root."
    go_to_repo_root "$FULL_COMMAND_PATH"
    print_info "Changed path to $PWD"
else
    go_to_repo_root "$PWD"
fi

REPO_ROOT_PATH="$PWD"

adb_checker

# Set default LOG_DIR if not provided
if [ -z "$LOG_DIR" ]; then
    LOG_DIR="$DEFAULT_LOG_DIR"
fi

BOARD=$(adb -s $SERIAL_NUMBER shell getprop ro.product.board)
ABI=$(adb -s $SERIAL_NUMBER shell getprop ro.product.cpu.abi)


if [ -z "$TEST_DIR" ]; then
    print_warn "Flag -td <test_dir> is not provided. Will use the default test directory"
    if [[ "$REPO_LIST_OUT" == *"device/google/cuttlefish"* ]]; then
        # In the platform repo
        print_info "Run test with atest"
        eval atest " ${TEST_NAMES[@]}" -s "$SERIAL_NUMBER"
        exit 0
    elif [[ "$BOARD" == "cutf"* ]] && [[ "$REPO_LIST_OUT" == *"common-modules/virtual-device"* ]]; then
        # In the android kernel repo
        if [[ "$ABI" == "arm64"* ]]; then
            TEST_DIR="/virtual_device_aarch64/tests.zip"
        elif [[ "$ABI" == "x86_64"* ]]; then
            TEST_DIR="/virtual_device_x86_64/tests.zip"
        else
            echo "$SERIAL_NUMBER is $ABI Cuttlefish. Not tests are supported at this time. Quit."
            exit 1
        fi
    elif [[ "$BOARD" == "raven"* || "$BOARD" == "oriole"* ]] && [[ "$REPO_LIST_OUT" == *"private/google-modules/display"* ]]; then
        TEST_DIR="out/slider/dist/tests.zip"
    elif [[ "$ABI" == "arm64"* ]] && [[ "$REPO_LIST_OUT" == *"kernel/common"* ]]; then
        TEST_DIR="out/kernel_aarch64/tests.zip"
    else
        echo "$SERIAL_NUMBER is $ABI $BOARD. Not supported at this time. Quit."
        exit 1
    fi
fi

TEST_FILERS=
for i in "$TEST_NAMES"; do
    TEST_NAME=$(echo $i | sed "s/:/ /g")
    TEST_FILTERS+=" --include-filter '$TEST_NAME'"
done

if [[ "$TEST_DIR" == "ab://"* ]]; then
    # Download test_file if it's remote file ab://
    fetch_cmd="$FULL_COMMAND_PATH/$FETCH_SCRIPT"
    cd "$REPO_ROOT_PATH/out"
    IFS='/' read -ra array <<< "$TEST_DIR"
    fetch_cmd+=" --branch ${array[2]}"
    fetch_cmd+=" --target ${array[3]}"
    if [[ "${array[4]}" != 'latest'* ]]; then
        fetch_cmd+=" --bid ${array[4]}"
    fi
    fetch_cmd+=" '${array[5]}'"
    if [ ! -d "${array[3]}" ]; then
        mkdir -p "${array[3]}"
    fi
    cd "${array[3]}"
    print_info "Download remote test file ${array[5]} to $PWD with: $fetch_cmd"
    eval "$fetch_cmd"
    TEST_DIR="$PWD/${array[5]}"
    cd "$REPO_ROOT_PATH"
fi

if [[ "$TEST_DIR" == *".zip"* ]]; then
    filename=${TEST_DIR##*/}
    new_test_dir=$(echo "$TEST_DIR" | sed "s/.zip//g")
    if [[ filename == "tests.zip" ]]; then
        if [ ! -d "$new_test_dir" ]; then
            mkdir -p "$new_test_dir"  # Create directory (including parents if needed)
            exit_code=$?
            if [ $exit_code -ne 0 ]; then # Check for errors during directory creation
                echo "Failed to create directory $new_test_dir."
                exit 1
            fi
        fi
        echo "Unzip $TEST_DIR to $new_test_dir"
        unzip -oq "$TEST_DIR" -d "$new_test_dir"
    else
        unzip -oq "$TEST_DIR" -d $(dirname "$new_test_dir")
    fi
    TEST_DIR="$new_test_dir" # Update TEST_DIR to the unzipped directory
fi

print_info "TEST_DIR=$TEST_DIR"

if [ -f "${TEST_DIR}/tools/vts-tradefed" ]; then
    TRADEFED="${TEST_DIR}/tools/vts-tradefed"
    print_info "Use vts-tradefed from ${TEST_DIR}/tools/vts-tradefed"
    tf_cli="$TRADEFED run commandAndExit \
    vts --skip-device-info --log-level-display info --log-file-path=$LOG_DIR \
    $TEST_FILTERS -s $SERIAL_NUMBER"
elif [ -f "${TEST_DIR}/tools/cts-tradefed" ]; then
    TRADEFED="${TEST_DIR}/tools/cts-tradefed"
    print_info "Use cts-tradefed from ${TEST_DIR}/tools/cts-tradefed"
    tf_cli="$TRADEFED run commandAndExit cts --skip-device-info \
    --log-level-display info --log-file-path=$LOG_DIR \
    $TEST_FILTERS -s $SERIAL_NUMBER"
elif [ -f "${ANDROID_HOST_OUT}/bin/tradefed.sh" ] ; then
    TRADEFED="${ANDROID_HOST_OUT}/bin/tradefed.sh"
    print_info "Use the tradefed from the local built path $TRADEFED"
    tf_cli="$TRADEFED run commandAndExit template/local_min \
    --log-level-display info --log-file-path=$LOG_DIR \
    --template:map test=suite/test_mapping_suite  --tests-dir=$TEST_DIR\
    $TEST_FILTERS -s $SERIAL_NUMBER"
elif [ -f "$PLATFORM_TF_PREBUILT" ]; then
    TRADEFED="JAVA_HOME=$PLATFORM_JDK_PATH PATH=$PLATFORM_JDK_PATH/bin:$PATH $PLATFORM_TF_PREBUILT"
    print_info "Local Tradefed is not built yet. Use the prebuilt from $PLATFORM_TF_PREBUILT"
    tf_cli="$TRADEFED run commandAndExit template/local_min \
    --log-level-display info --log-file-path=$LOG_DIR \
    --template:map test=suite/test_mapping_suite  --tests-dir=$TEST_DIR\
    $TEST_FILTERS -s $SERIAL_NUMBER"
elif [ -f "$KERNEL_TF_PREBUILT" ]; then
    TRADEFED="JAVA_HOME=$JDK_PATH PATH=$JDK_PATH/bin:$PATH $KERNEL_TF_PREBUILT"
    print_info "Use the tradefed prebuilt from $KERNEL_TF_PREBUILT"
    tf_cli="$TRADEFED run commandAndExit template/local_min \
    --log-level-display info --log-file-path=$LOG_DIR \
    --template:map test=suite/test_mapping_suite  --tests-dir=$TEST_DIR\
    $TEST_FILTERS -s $SERIAL_NUMBER"
# No Tradefed found
else
    print_info "Can not find Tradefed binary. Please use flag -tf to specify the binary path."
    exit 1
fi

# Construct the TradeFed command

# Add GCOV options if enabled
if $GCOV; then
    tf_cli+=" --coverage --coverage-toolchain GCOV_KERNEL --auto-collect GCOV_KERNEL_COVERAGE"
fi

# Evaluate the TradeFed command with extra arguments
print_info "Run test with: $tf_cli" "${EXTRA_ARGS[@]}"
eval "$tf_cli" "${EXTRA_ARGS[@]}"


