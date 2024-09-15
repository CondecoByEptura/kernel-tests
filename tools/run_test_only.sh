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
DOWNLOAD_PATH="/tmp/downloaded"
GCOV=false
FETCH_SCRIPT="kernel/tests/tools/fetch_artifact.sh"
TRADEFED=
TEST_ARGS=()
TEST_DIR=
TEST_NAMES=()

BOLD="$(tput bold)"
END="$(tput sgr0)"
GREEN="$(tput setaf 2)"
RED="$(tput setaf 198)"
YELLOW="$(tput setaf 3)"
BLUE="$(tput setaf 34)"

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
    echo "[$MY_NAME]: ${GREEN}$1${END}"
}

function print_warn() {
    echo "[$MY_NAME]: ${YELLOW}$1${END}"
}

function print_error() {
    echo -e "[$MY_NAME]: ${RED}$1${END}"
    cd $OLD_PWD
    exit 1
}

function print_help() {
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
    echo "  -tl <test_log_dir>, --test_log=<test_log_dir>"
    echo "                        The test log dir. Use default out/test_logs if not specified."
    echo "  -ta <extra_arg>, --extra-arg=<extra_arg>"
    echo "                        Additional tradefed command arg. Can be repeated."
    echo "  -t <test_name>, --test=<test_name>  The test name. Can be repeated."
    echo "                        If test is not specified, no tests will be run."
    echo "  -tf <tradefed_binary_path>, --tradefed-bin=<tradefed_binary_path>"
    echo "                        The alternative tradefed binary to run test with."
    echo "  --skip-build          Skip the platform build step. Will build by default if in repo."
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
    echo "$0 -s 1C141FDEE003FH -t CtsAccessibilityTestCases -td <your_path_to_platform_repo>"
    echo ""
    exit 0
}

function set_platform_repo () {
    print_warn "Build target product '${TARGET_PRODUCT}' does not match device product '$PRODUCT'"
    lunch_cli="source build/envsetup.sh && "
    if [ -f "build/release/release_configs/trunk_staging.textproto" ]; then
        lunch_cli+="lunch $PRODUCT-trunk_staging-$BUILD_TYPE"
    else
        lunch_cli+="lunch $PRODUCT-trunk_staging-$BUILD_TYPE"
    fi
    print_info "Setup build environment with: $lunch_cli"
    eval "$lunch_cli"
}

function run_test_in_platform_repo () {
    if [ -z "${TARGET_PRODUCT}" ]; then
        set_platform_repo
    elif [[ "${TARGET_PRODUCT}" != *"x86"* && "${PRODUCT}" == *"x86"* ]] || \
       [[ "${TARGET_PRODUCT}" == *"x86"* && "${PRODUCT}" != *"x86"* ]]; then
       set_platform_repo
    fi
    eval atest " ${TEST_NAMES[@]}" -s "$SERIAL_NUMBER"
    exit_code=$?
    cd $OLD_PWD
    exit $exit_code
}

OLD_PWD=$PWD
MY_NAME=${0##*/}

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
                print_error "device serial is not specified"
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
                print_error "test log directory is not specified"
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
                print_error "test directory is not specified"
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
                print_error "test arg is not specified"
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
                print_error "test name is not specified"
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
                print_error "tradefed binary is not specified"
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

# Ensure SERIAL_NUMBER is provided
if [ -z "$SERIAL_NUMBER" ]; then
    print_error "Device serial is not provided with flag -s <serial_number>."
fi

# Ensure TEST_NAMES is provided
if [ -z "$TEST_NAMES" ]; then
    print_error "No test is specified with flag -t <test_name>."
fi

FULL_COMMAND_PATH=$(dirname "$PWD/$0")
REPO_LIST_OUT=$(repo list 2>&1)
if [[ "$REPO_LIST_OUT" == "error"* ]]; then
    print_warn "Current path $PWD is not in an Android repo. Change path to repo root."
    go_to_repo_root "$FULL_COMMAND_PATH"
    print_info "Changed path to $PWD"
else
    go_to_repo_root "$PWD"
fi

REPO_ROOT_PATH="$PWD"
FETCH_SCRIPT="$REPO_ROOT_PATH/$FETCH_SCRIPT"

adb_checker

# Set default LOG_DIR if not provided
if [ -z "$LOG_DIR" ]; then
    LOG_DIR="$DEFAULT_LOG_DIR"
fi

BOARD=$(adb -s $SERIAL_NUMBER shell getprop ro.product.board)
ABI=$(adb -s $SERIAL_NUMBER shell getprop ro.product.cpu.abi)
PRODUCT=$(adb -s $SERIAL_NUMBER shell getprop ro.product.name)
BUILD_TYPE=$(adb -s $SERIAL_NUMBER shell getprop ro.build.type)

if [ -z "$TEST_DIR" ]; then
    print_warn "Flag -td <test_dir> is not provided. Will use the default test directory"
    if [[ "$REPO_LIST_OUT" == *"vendor/google/tools"* ]]; then
        # In the platform repo
        print_info "Run test with atest"
        run_test_in_platform_repo
    elif [[ "$BOARD" == "cutf"* ]] && [[ "$REPO_LIST_OUT" == *"common-modules/virtual-device"* ]]; then
        # In the android kernel repo
        if [[ "$ABI" == "arm64"* ]]; then
            TEST_DIR="$REPO_ROOT_PATH/out/virtual_device_aarch64/dist/tests.zip"
        elif [[ "$ABI" == "x86_64"* ]]; then
            TEST_DIR="$REPO_ROOT_PATH/out/virtual_device_x86_64/dist/tests.zip"
        else
            print_error "No test builds for $ABI Cuttlefish in $REPO_ROOT_PATH"
        fi
    elif [[ "$BOARD" == "raven"* || "$BOARD" == "oriole"* ]] && [[ "$REPO_LIST_OUT" == *"private/google-modules/display"* ]]; then
        TEST_DIR="$REPO_ROOT_PATH/out/slider/dist/tests.zip"
    elif [[ "$ABI" == "arm64"* ]] && [[ "$REPO_LIST_OUT" == *"kernel/common"* ]]; then
        TEST_DIR="$REPO_ROOT_PATH/out/kernel_aarch64/dist/tests.zip"
    else
        print_error "No test builds for $ABI $BOARD in $REPO_ROOT_PATH"
    fi
fi

TEST_FILTERS=
for i in "$TEST_NAMES"; do
    TEST_NAME=$(echo $i | sed "s/:/ /g")
    TEST_FILTERS+=" --include-filter '$TEST_NAME'"
done

if [[ "$TEST_DIR" == ab://* ]]; then
    # Download test_file if it's remote file ab://
    if [ -d "$DOWNLOAD_PATH" ]; then
        rm -rf $DOWNLOAD_PATH
    fi
    mkdir -p "$DOWNLOAD_PATH" || $(print_error "Fail to create directory $DOWNLOAD_PATH")
    cd $DOWNLOAD_PATH || $(print_error "Fail to go to $DOWNLOAD_PATH")
    file_name=${TEST_DIR##*/}
    eval "$FETCH_SCRIPT $TEST_DIR"
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        print_info "$TEST_DIR is downloaded succeeded"
    else
        print_error "Failed to download $TEST_DIR"
    fi

    file_name=$(ls $file_name)
    # Check if the download was successful
    if [ ! -f "${file_name}" ]; then
        print_error "Failed to download ${file_name}"
    fi
    TEST_DIR="$DOWNLOAD_PATH/$file_name"
elif [ ! -z "$TEST_DIR" ]; then
    if [ -d $TEST_DIR ]; then
        test_file_path=$TEST_DIR
    elif [ -f "$TEST_DIR" ]; then
        test_file_path=$(dirname "$TEST_DIR")
    else
        print_error "$TEST_DIR is neither a directory or file"
    fi
    cd "$test_file_path" || $(print_error "Failed to go to $test_file_path")
    TEST_REPO_LIST_OUT=$(repo list 2>&1)
    if [[ "$TEST_REPO_LIST_OUT" == "error"* ]]; then
        print_info "Test path $test_file_path is not in an Android repo. Will use $TEST_DIR directly."
    elif [[ "$TEST_REPO_LIST_OUT" == *"vendor/google/tools"* ]]; then
        # Test_dir is from the platform repo
        print_info "Test_dir $TEST_DIR is from Android platform repo. Run test with atest"
        go_to_repo_root "$PWD"
        run_test_in_platform_repo
    fi
fi

cd "$REPO_ROOT_PATH"
if [[ "$TEST_DIR" == *".zip"* ]]; then
    filename=${TEST_DIR##*/}
    new_test_dir="$REPO_ROOT_PATH/out/tests"
    if [ ! -d "$new_test_dir" ]; then
        mkdir -p "$new_test_dir" || $(print_error "Failed to make directory $new_test_dir")
    fi
    unzip -oq "$TEST_DIR" -d "$new_test_dir" || $(print_error "Failed to unzip $TEST_DIR to $new_test_dir")
    case $filename in
        "android-vts.zip" | "android-cts.zip")
        new_test_dir+="/$(echo $filename | sed "s/.zip//g")"
        ;;
        *)
        ;;
    esac
    TEST_DIR="$new_test_dir" # Update TEST_DIR to the unzipped directory
fi

print_info "Will run tests with test artifacts in $TEST_DIR"

if [ -f "${TEST_DIR}/tools/vts-tradefed" ]; then
    TRADEFED="${TEST_DIR}/tools/vts-tradefed"
    print_info "Will run tests with vts-tradefed from $TRADEFED"
    tf_cli="$TRADEFED run commandAndExit \
    vts --skip-device-info --log-level-display info --log-file-path=$LOG_DIR \
    $TEST_FILTERS -s $SERIAL_NUMBER"
elif [ -f "${TEST_DIR}/tools/cts-tradefed" ]; then
    TRADEFED="${TEST_DIR}/tools/cts-tradefed"
    print_info "Will run tests with cts-tradefed from $TRADEFED"
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
    print_error "Can not find Tradefed binary. Please use flag -tf to specify the binary path."
fi

# Construct the TradeFed command

# Add GCOV options if enabled
if $GCOV; then
    tf_cli+=" --coverage --coverage-toolchain GCOV_KERNEL --auto-collect GCOV_KERNEL_COVERAGE"
fi

# Evaluate the TradeFed command with extra arguments
print_info "Run test with: $tf_cli" "${EXTRA_ARGS[*]}"
eval "$tf_cli" "${EXTRA_ARGS[*]}"
exit_code=$?
cd $OLD_PWD
exit $exit_code
