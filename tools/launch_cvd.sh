#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

# A handy tool to launch CVD with local build or remote build.

# Constants
ACLOUD_PREBUILT="prebuilts/asuite/acloud/linux-x86/acloud"
OPT_SKIP_PRERUNCHECK='--skip-pre-run-check'
# Color constants
BOLD="$(tput bold)"
END="$(tput sgr0)"
GREEN="$(tput setaf 2)"
RED="$(tput setaf 198)"
YELLOW="$(tput setaf 3)"
BLUE="$(tput setaf 34)"

SKIP_BUILD=false
GCOV=false
DEBUG=false
KASAN=false
EXTRA_OPTIONS=()
LOCAL_REPO=

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
    echo "[$MY_NAME] ${GREEN}$1${END}"
}

function print_warn() {
    echo "[$MY_NAME] ${YELLOW}$1${END}"
}

function print_error() {
    echo -e "[$MY_NAME] ${RED}$1${END}"
    cd $OLD_PWD
    exit 1
}

function print_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "This script will build images and launch a Cuttlefish device."
    echo ""
    echo "Available options:"
    echo "  --skip-build          Skip the image build step. Will build by default if in repo."
    echo "  --gcov                Launch CVD with gcov enabled kernel"
    echo "  --debug               Launch CVD with debug enabled kernel"
    echo "  --kasan               Launch CVD with kasan enabled kernel"
    echo "  -pb <platform_build>, --platform-build=<platform_build>"
    echo "                        The platform build path. Can be a local path or a remote build"
    echo "                        as ab://<branch>/<build_target>/<build_id>."
    echo "                        If not specified, it will use the platform build in the local"
    echo "                        repo, or the default compatible platform build for the kernel."
    echo "  -sb <system_build>, --system-build=<system_build>"
    echo "                        The system build path for GSI testing. Can be a local path or"
    echo "                        remote build as ab://<branch>/<build_target>/<build_id>."
    echo "                        If not specified, no system build will be used."
    echo "  -kb <kernel_build>, --kernel-build=<kernel_build>"
    echo "                        The kernel build path. Can be a local path or a remote build"
    echo "                        as ab://<branch>/<build_target>/<build_id>."
    echo "                        If not specified, it will use the kernel in the local repo."
    echo "  --acloud-arg=<acloud_arg>"
    echo "                        Additional acloud command arg. Can be repeated."
    echo "                        For example --acloud-arg=--local-instance to launch a local cvd."
    echo "  -h, --help            Display this help message and exit"
    echo ""
    echo "Examples:"
    echo "$0"
    echo "$0 --acloud-arg=--local-instance"
    echo "$0 -pb ab://git_main/aosp_cf_x86_64_phone-userdebug/latest"
    echo "$0 -pb ~/aosp-main/out/target/product/vsoc_x86_64/"
    echo "$0 -kb ~/android-mainline/out/virtual_device_x86_64/"
    echo ""
    exit 0
}

OLD_PWD=$PWD
MY_NAME=${0##*/}

while test $# -gt 0; do
    case "$1" in
        -h|--help)
            print_help
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -pb)
            shift
            if test $# -gt 0; then
                PLATFORM_BUILD=$1
            else
                print_error "platform build is not specified"
            fi
            shift
            ;;
        --platform-build*)
            PLATFORM_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
            shift
            ;;
        -sb)
            shift
            if test $# -gt 0; then
                SYSTEM_BUILD=$1
            else
                print_error "system build is not specified"
            fi
            shift
            ;;
        --system-build*)
            SYSTEM_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
            shift
            ;;
        -kb)
            shift
            if test $# -gt 0; then
                KERNEL_BUILD=$1
            else
                print_error "kernel build path is not specified"
            fi
            shift
            ;;
        --kernel-build*)
            KERNEL_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
            shift
            ;;
        --acloud-arg*)
            EXTRA_OPTIONS+=$(echo $1 | sed -e "s/^[^=]*=//g")
            shift
            ;;
        --acloud-bin*)
            ACLOUD_BIN=$(echo $1 | sed -e "s/^[^=]*=//g")
            shift
            ;;
        --gcov)
            GCOV=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --kasan)
            KASAN=true
            shift
            ;;
        *)
            print_error "Unsupported flag: $1" >&2
            shift
            ;;
    esac
done


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

if [[ "$REPO_LIST_OUT" == *common-modules/virtual-device* ]] && [[ "$REPO_LIST_OUT" == *kernel/common* ]]; then
    if [ -z "$KERNEL_BUILD" ] && [ "$SKIP_BUILD" == false ]; then
        if [ ! -f "common-modules/virtual-device/BUILD.bazel" ]; then
            # TODO: Add build support to android12 and earlier kernels
            print_error "bazel build common-modules/virtual-device is not supported in this kernel tree"
        fi
        KERNEL_VERSION=$(cat .repo/manifests/default.xml | grep common-modules/virtual-device | grep -oP 'revision="\K[^"]*')
        # Build a new kernel
        build_cmd="tools/bazel run --config=fast"
        if $GCOV; then
            build_cmd+=" --gcov"
        fi
        if $DEBUG; then
            build_cmd+=" --debug"
        fi
        if $KASAN; then
            build_cmd+=" --kasan"
        fi
        build_cmd+=" //common-modules/virtual-device:virtual_device_x86_64_dist"
        print_warn "Flag --skip build is not set. Rebuild the kernel with: $build_cmd."
        eval $build_cmd
        exit_code=$?
        if [ $exit_code -eq 0 ]; then
            print_info "$build_cmd succeeded"
        else
            print_error "$build_cmd failed"
        fi
        KERNEL_BUILD="$PWD/out/virtual_device_x86_64"
    elif $SKIP_BUILD && [ -d "out/virtual_device_x86_64"]; then
        KERNEL_BUILD="$PWD/out/virtual_device_x86_64"
    fi
elif [[ "$REPO_LIST_OUT" == *device/google/cuttlefish* ]]; then
    if [ -z "$PLATFORM_BUILD" ] && [ "$SKIP_BUILD" == false ]; then
        if [ -z "${TARGET_PRODUCT}"] || [[ "${TARGET_PRODUCT}" != *"cf_x86"* ]]; then
            print_info "TARGET_PRODUCT=${TARGET_PRODUCT}"
            print_error "please setup your build environment by: source build/envsetup.sh && lunch <cf_target>"
        fi
        build_cmd="m -j12"
        print_warn "Flag --skip build is not set. Rebuilt platform images with: $build_cmd"
        eval $build_cmd
        exit_code=$?
        if [ $exit_code -eq 0 ]; then
            print_info "$build_cmd succeeded"
        else
            print_error "$build_cmd failed"
        fi
        PLATFORM_BUILD=${ANDROID_PRODUCT_OUT}
    elif $SKIP_BUILD && [ -f "${ANDROID_PRODUCT_OUT}/system.img" ]; then
        PLATFORM_BUILD=${ANDROID_PRODUCT_OUT}
    fi
fi

adb_checker

if [ -z "$ACLOUD_BIN" ]; then
    output=$(which acloud 2>&1) # Capture both stdout and stderr
    if [ -z "$output" ]; then # Check if 'which acloud' found anything
        print_info "Use acloud binary from prebuilt"
        ACLOUD_BIN="$ACLOUD_PREBUILT"
    else
        print_info "Use acloud binary from $output"
        ACLOUD_BIN="$output"
    fi
else
    print_info "Use acloud binary specified with --acloud-bin"
fi

acloud_cli="$ACLOUD_BIN create"
EXTRA_OPTIONS+=("$OPT_SKIP_PRERUNCHECK")
# Add in branch if not specified

echo "KERNEL_BUILD=$KERNEL_BUILD"
echo "VENDOR_KERNEL_BUILD=$VENDOR_KERNEL_BUILD"
echo "PLATFORM_BUILD=$PLATFORM_BUILD"

if [ -z "$PLATFORM_BUILD" ]; then
    print_warn "Platform build is not specified, will use the latest aosp-main build."
    acloud_cli+=' --branch aosp-main'
elif [[ "$PLATFORM_BUILD" == ab://* ]]; then
    IFS='/' read -ra array <<< "$PLATFORM_BUILD"
    acloud_cli+=" --branch ${array[2]}"

    # Check if array[3] exists before using it
    if [ ${#array[@]} -ge 3 ] && [ ! -z "${array[3]}" ]; then
        acloud_cli+=" --build-target ${array[3]}"

        # Check if array[4] exists and is not 'latest' before using it
        if [ ${#array[@]} -ge 4 ] && [ ! -z "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
            acloud_cli+=" --build-id ${array[4]}"
        fi
    fi
else
    acloud_cli+=" --local-image $PLATFORM_BUILD"
fi

if [ -z "$KERNEL_BUILD" ]; then
    print_warn "Flag --kernel-build is not set, will not launch Cuttlefish with different kernel."
elif [ "$PLATFORM_BUILD" == "ab://"* ]; then
    IFS='/' read -ra array <<< "$PLATFORM_BUILD"
    acloud_cli+=" --kernel-branch ${array[2]}"
    if [ ! -z ${array[3]}]; then
        acloud_cli+=" --kernel-build-target ${array[3]}"
        if [ ! -z ${array[4]}] && [ ${array[4]} != 'latest']; then
            acloud_cli+=" --kernel-build-id ${array[4]}"
        fi
    fi
else
    acloud_cli+=" --local-kernel-image $KERNEL_BUILD"
fi

if [ -z "$SYSTEM_BUILD" ]; then
    print_warn "System build is not specified, will not launch Cuttlefish with GSI mixed build."
elif [ "$SYSTEM_BUILD" == "ab://"* ]; then
    IFS='/' read -ra array <<< "$SYSTEM_BUILD"
    acloud_cli+=" --system-branch ${array[2]}"
    if [ ! -z ${array[3]}]; then
        acloud_cli+=" --system-build-target ${array[3]}"
        if [ ! -z ${array[4]}] && [ ${array[4]} != 'latest']; then
            acloud_cli+=" --system-build-id ${array[4]}"
        fi
    fi
else
    acloud_cli+=" --local-system-image $SYSTEM_BUILD"
fi

acloud_cli+=" ${EXTRA_OPTIONS[@]}"
print_info "Launch CVD with command: $acloud_cli"
eval "$acloud_cli"

