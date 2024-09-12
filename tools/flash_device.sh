#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

# A handy tool to launch CVD with local build or remote build.

# Constants
FETCH_SCRIPT="fetch_artifact.sh"
# Please see go/cl_flashstation
FLASH_CLI=/google/bin/releases/android/flashstation/cl_flashstation
LOCAL_FLASH_CLI=/google/bin/releases/android/flashstation/local_flashstation
REMOTE_MIX_SCRIPT_PATH="DATA/local/tmp/build_mixed_kernels_ramdisk"
FETCH_SCRIPT="kernel/tests/tools/fetch_artifact.sh"
DOWNLOAD_PATH="/tmp/downloaded_images"
KERNEL_TF_PREBUILT=prebuilts/tradefed/filegroups/tradefed/tradefed.sh
PLATFORM_TF_PREBUILT=tools/tradefederation/prebuilts/filegroups/tradefed/tradefed.sh
JDK_PATH=prebuilts/jdk/jdk11/linux-x86
PLATFORM_JDK_PATH=prebuilts/jdk/jdk21/linux-x86
LOG_DIR=$PWD/out/test_logs/$(date +%Y%m%d_%H%M%S)
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
DEVICE_VARIANT="userdebug"

function print_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "This script will build images and launch a Cuttlefish device."
    echo ""
    echo "Available options:"
    echo "  -s <serial_number>, --serial=<serial_number>"
    echo "                        The device serial number to run tests with."
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
    echo "  --device-variant=<device_variant>"
    echo "                        Device variant such as userdebug, user, or eng."
    echo "                        If not specified, will be userdebug by default."
    echo "  -h, --help            Display this help message and exit"
    echo ""
    echo "Examples:"
    echo "$0"
    echo "$0 -s 1C141FDEE003FH"
    echo "$0 -s 1C141FDEE003FH -pb ab://git_main/raven-userdebug/latest"
    echo "$0 -s 1C141FDEE003FH -pb ~/aosp-main"
    echo "$0 -s 1C141FDEE003FH -vkb ~/pixel-mainline -pb ab://git_main/raven-userdebug/latest"
    echo "$0 -s 1C141FDEE003FH -vkb ab://kernel-android-gs-pixel-mainline/kernel_raviole_kleaf/latest \
    -pb ab://git_trunk_pixel_kernel_61-release/raven-userdebug/latest \
    -kb ab://aosp_kernel-common-android-mainline/kernel_aarch64/latest"
    echo ""
    exit 0
}

function parse_arg() {
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
            --platform-build=*)
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
            --system-build=*)
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
            --kernel-build=*)
                KERNEL_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
                shift
                ;;
            -vkb)
                shift
                if test $# -gt 0; then
                    VENDOR_KERNEL_BUILD=$1
                else
                    print_error "vendor kernel build path is not specified"
                fi
                shift
                ;;
            --pixel-kernel-build=*)
                VENDOR_KERNEL_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
                shift
                ;;
            --device-variant=*)
                DEVICE_VARIANT=$(echo $1 | sed -e "s/^[^=]*=//g")
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
}

function adb_checker() {
    if ! which adb &> /dev/null; then
        print_error "adb not found!"
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

function set_platform_repo () {
    print_warn "Build target product '${TARGET_PRODUCT}' does not match expected $1"
    local lunch_cli="source build/envsetup.sh && lunch $1"
    if [ -f "build/release/release_configs/trunk_staging.textproto" ]; then
        lunch_cli+="-trunk_staging-$DEVICE_VARIANT"
    else
        lunch_cli+="-$DEVICE_VARIANT"
    fi
    print_info "Setup build environment with: $lunch_cli"
    eval "$lunch_cli"
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        print_info "$lunch_cli succeeded"
    else
        print_error "$lunch_cli failed"
    fi
}

function find_repo () {
    manifest_output=$(grep -e "superproject" -e "gs-pixel" -e "private/google-modules/soc/gs" \
    -e "kernel/common" -e "common-modules/virtual-device" .repo/manifests/default.xml)
    case "$manifest_output" in
        *platform/superproject*)
            PLATFORM_REPO_ROOT="$PWD"
            PLATFORM_VERSION=$(grep -e "platform/superproject" .repo/manifests/default.xml | \
            grep -oP 'revision="\K[^"]*')
            print_info "PLATFORM_REPO_ROOT=$PLATFORM_REPO_ROOT, PLATFORM_VERSION=$PLATFORM_VERSION"
            if [ -z "$PLATFORM_BUILD" ]; then
                PLATFORM_BUILD="$PLATFORM_REPO_ROOT"
            fi
            ;;
        *kernel/superproject*)
            if [[ "$manifest_output" == *private/google-modules/soc/gs* ]]; then
                VENDOR_KERNEL_REPO_ROOT="$PWD"
                VENDOR_KERNEL_VERSION=$(grep -e "default revision" .repo/manifests/default.xml | \
                grep -oP 'revision="\K[^"]*')
                print_info "VENDOR_KERNEL_REPO_ROOT=$VENDOR_KERNEL_REPO_ROOT, VENDOR_KERNEL_VERSION=$VENDOR_KERNEL_VERSION"
                if [ -z "$VENDOR_KERNEL_BUILD" ]; then
                    VENDOR_KERNEL_BUILD="$VENDOR_KERNEL_REPO_ROOT"
                fi
            elif [[ "$manifest_output" == *common-modules/virtual-device* ]]; then
                KERNEL_REPO_ROOT="$PWD"
                KERNEL_VERSION=$(grep -e "kernel/superproject" \
                .repo/manifests/default.xml | grep -oP 'revision="common-\K[^"]*')
                print_info "KERNEL_REPO_ROOT=$KERNEL_REPO_ROOT, KERNEL_VERSION=$KERNEL_VERSION"
                if [ -z "$KERNEL_BUILD" ]; then
                    KERNEL_BUILD="$KERNEL_REPO_ROOT"
                fi
            fi
            ;;
        *)
            print_warn "Unexpected manifest output. Could not determine repository type."
            ;;
    esac
}

function build_platform () {
    build_cmd="m -j12"
    print_warn "Flag --skip-build is not set. Rebuilt images at $PWD with: $build_cmd"
    eval $build_cmd
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        if [ -f "${ANDROID_PRODUCT_OUT}/system.img" ]; then
            print_info "$build_cmd succeeded"
        else
            print_error "${ANDROID_PRODUCT_OUT}/system.img doesn't exist"
        fi
    else
        print_warn "$build_cmd returned exit_code $exit_code or ${ANDROID_PRODUCT_OUT}/system.img is not found"
        print_error "$build_cmd failed"
    fi
}

function build_slider () {
    local build_cmd="tools/bazel run --config=fast"
    build_cmd+=" //private/google-modules/soc/gs:slider_dist"
    print_warn "Flag --skip build is not set. Rebuild the kernel with: $build_cmd."
    eval "$build_cmd"
    if [ $exit_code -eq 0 ]; then
        print_info "Build kernel succeeded"
    else
        print_error "Build kernel failed with exit code $exit_code"
    fi
}

function build_ack () {
    build_cmd="tools/bazel run --config=fast"
    if [ "$GCOV" = true ]; then
        build_cmd+=" --gcov"
    fi
    if [ "$DEBUG" = true ]; then
        build_cmd+=" --debug"
    fi
    if [ "$KASAN" = true ]; then
        build_cmd+=" --kasan"
    fi
    build_cmd+=" //common:kernel_aarch64_dist"
    print_warn "Flag --skip-build is not set. Rebuild the kernel with: $build_cmd."
    eval $build_cmd
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        print_info "$build_cmd succeeded"
    else
        print_error "$build_cmd failed"
    fi
}

function download_platform_build() {
    print_info "Downloading $1 to $PWD"
    local build_info="$1"
    local file_patterns=("$PRODUCT-img-*.zip" "bootloader.img" "radio.img" "vendor_ramdisk.img" "misc_info.txt" "otatools.zip")

    for pattern in "${file_patterns[@]}"; do
        download_file_name="$build_info/$pattern"
        eval "$FETCH_SCRIPT $download_file_name"
        exit_code=$?
        if [ $exit_code -eq 0 ]; then
            print_info "Download $download_file_name succeeded"
        else
            print_error "Download $download_file_name failed"
        fi
    done
    echo ""
}

function download_gki_build() {
    print_info "Downloading $1 to $PWD"
    local build_info="$1"
    local file_patterns=("Image.lz4" "boot-lz4.img" "system_dlkm_staging_archive.tar.gz" "system_dlkm.flatten.ext4.img" "system_dlkm.flatten.erofs.img")

    for pattern in "${file_patterns[@]}"; do
        download_file_name="$build_info/$pattern"
        eval "$FETCH_SCRIPT $download_file_name"
        exit_code=$?
        if [ $exit_code -eq 0 ]; then
            print_info "Download $download_file_name succeeded"
        else
            print_error "Download $download_file_name failed"
        fi
    done
    echo ""
}

function download_vendor_kernel_build() {
    print_info "Downloading $1 to $PWD"
    local build_info="$1"
    local file_patterns=("vendor_dlkm_staging_archive.tar.gz" "Image.lz4" "dtbo.img" \
    "initramfs.img" "vendor_dlkm.img" "boot.img" "vendor_dlkm.modules.blocklist" "vendor_dlkm.modules.load" )

    if [[ "$VENDOR_KERNEL_VERSION" == *"6.6" ]]; then
        file_patterns+="*vendor_dev_nodes_fragment.img"
    fi

    case "$PRODUCT" in
        oriole | raven | bluejay)
            file_patterns+=("gs101-a0.dtb" "gs101-b0.dtb")
            ;;
        *)
            ;;
    esac
    for pattern in "${file_patterns[@]}"; do
        download_file_name="$build_info/$pattern"
        eval "$FETCH_SCRIPT $download_file_name"
        exit_code=$?
        if [ $exit_code -eq 0 ]; then
            print_info "Download $download_file_name succeeded"
        else
            print_error "Download $download_file_name failed"
        fi
    done
    echo ""
}

function flash_gki_build() {
    tf_cli="$TRADEFED \
    run commandAndExit template/local_min --log-level-display info \
    --log-file-path=$LOG_DIR -s $SERIAL_NUMBER \
    --template:map preparers=template/preparers/gki-device-flash-preparer \
    --extra-file gki_boot.img=$KERNEL_BUILD/boot-lz4.img \
    --extra-file system_dlkm.img=$KERNEL_BUILD/system_dlkm.img \
    --wipe-device-after-gki-flash"
    eval $tf_cli
}

function flash_vendor_kernel_build() {
    tf_cli="$TRADEFED \
    run commandAndExit template/local_min --log-level-display info \
    --log-file-path=$LOG_DIR -s $SERIAL_NUMBER \
    --template:map preparers=template/preparers/gki-device-flash-preparer \
    --extra-file gki_boot.img=$VENDOR_KERNEL_BUILD/boot.img \
    --extra-file initramfs.img=$VENDOR_KERNEL_BUILD/initramfs.img \
    --extra-file dtbo.img=$VENDOR_KERNEL_BUILD/dtbo.img \
    --extra-file vendor_dlkm.img=$VENDOR_KERNEL_BUILD/vendor_dlkm.img \
    --wipe-device-after-gki-flash"
    eval $tf_cli
}

function flash_platform_build() {
    tf_cli="$TRADEFED \
    run commandAndExit template/local_min --log-level-display info \
    --log-file-path=$LOG_DIR -s $SERIAL_NUMBER \
    --template:map preparers=template/preparers/fastboot-flash-preparer \
    --bootloader-image $PLATFORM_BUILD/bootloader.img \
    --baseband-image $PLATFORM_BUILD/radio.img \
    --device-image $PLATFORM_BUILD/*-img-*.zip --userdata-flash WIPE"
    eval $tf_cli
}

function get_mix_ramdisk_script() {
    download_file_name="ab://git_main/aosp_cf_x86_64_only_phone-trunk_staging-userdebug/latest/*-tests-*.zip"
    eval "$FETCH_SCRIPT $download_file_name"
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        print_info "Download $download_file_name succeeded"
    else
        print_error "Download $download_file_name failed"
    fi
    eval "unzip -j *-tests-* DATA/local/tmp/build_mixed_kernels_ramdisk"
    echo ""
}

function mixing_build() {
    if [ ! -z ${PLATFORM_REPO_ROOT_PATH} ] && [ -f "$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/build_mixed_kernels_ramdisk"]; then
        mix_kernel_cmd="$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/build_mixed_kernels_ramdisk"
    elif [ -f "$DOWNLOAD_PATH/build_mixed_kernels_ramdisk" ]; then
        mix_kernel_cmd="$DOWNLOAD_PATH/build_mixed_kernels_ramdisk"
    else
        cd "$DOWNLOAD_PATH"
        get_mix_ramdisk_script
        mix_kernel_cmd="$PWD/build_mixed_kernels_ramdisk"
    fi
    if [ ! -f "$mix_kernel_cmd" ] || [ ! -z"$mix_kernel_cmd" ]; then
        print_error "$mix_kernel_cmd doesn't exist or is not executable"
    fi
    if [ -d "$DOWNLOAD_PATH/new_device_dir" ]; then
        rm -rf "$DOWNLOAD_PATH/new_device_dir"
    fi
    local new_device_dir="$DOWNLOAD_PATH/new_device_dir"
    mkdir -p "$device_dir"
    local mixed_build_cmd="$mix_kernel_cmd"
    if [ -d "${KERNEL_BUILD}" ]; then
        mixed_build_cmd+=" --gki_dir $KERNEL_BUILD"
    fi
    mixed_build_cmd+=" $PLATFORM_BUILD $VENDOR_KERNEL_BUILD $new_device_dir"
    print_info "Run: $mixed_build_cmd"
    eval $mixed_build_cmd
    device_image=$(ls $new_device_dir/*-img-*.zip)
    if [ ! -f "$device_image" ]; then
        print_error "New device image is not created in $new_device_dir"
    fi
    cp "$PLATFORM_BUILD"/bootloader.img $new_device_dir/.
    cp "$PLATFORM_BUILD"/radio.img $new_device_dir/.
    PLATFORM_BUILD="$new_device_dir"
}

adb_checker

LOCAL_REPO=

OLD_PWD=$PWD
MY_NAME=$0

parse_arg "$@"

if [ -z "$SERIAL_NUMBER" ]; then
    print_error "Device serial is not provided with flag -s <serial_number>."
    exit 1
fi

BOARD=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.board)
ABI=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.cpu.abi)
PRODUCT=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.name)
BUILD_TYPE=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.type)
DEVICE_KERNEL_STRING=$(adb -s "$SERIAL_NUMBER" shell uname -r)
SYSTEM_DLKM_VERSION=$(adb -s "$SERIAL_NUMBER" shell getprop ro.system_dlkm.build.version.release)

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
FETCH_SCRIPT="$REPO_ROOT_PATH/$FETCH_SCRIPT"

find_repo

if [ ! -d "$DOWNLOAD_PATH" ]; then
    mkdir -p "$DOWNLOAD_PATH" || $(print_error "Fail to create directory $DOWNLOAD_PATH")
fi

if [[ "$PLATFORM_BUILD" == ab://* ]]; then
    print_info "Download platform build $PLATFORM_BUILD"
    if [ -d "$DOWNLOAD_PATH/device_dir" ]; then
        rm -rf "$DOWNLOAD_PATH/device_dir"
    fi
    PLATFORM_DIR="$DOWNLOAD_PATH/device_dir"
    mkdir -p "$PLATFORM_DIR"
    cd "$PLATFORM_DIR" || $(print_error "Fail to go to $PLATFORM_DIR")
    download_platform_build "$PLATFORM_BUILD"
    PLATFORM_BUILD="$PLATFORM_DIR"
elif [ ! -z "$PLATFORM_BUILD" ] && [ -d "$PLATFORM_BUILD" ]; then
    # Check if PLATFORM_BUILD is an Android platform repo, if yes rebuild
    cd "$PLATFORM_BUILD"
    PLATFORM_REPO_LIST_OUT=$(repo list 2>&1)
    if [[ "$PLATFORM_REPO_LIST_OUT" != "error"* ]]; then
        go_to_repo_root "$PWD"
        if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
            find_repo
        fi
        if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "$PRODUCT" ]]; then
            set_platform_repo $PRODUCT
            if [ "$SKIP_BUILD" = false ]; then
                build_platform
            fi
            PLATFORM_BUILD="${ANDROID_PRODUCT_OUT}"
        fi
    fi
fi

if [[ "$SYSTEM_BUILD" == ab://* ]]; then
    print_warn "System build is not supoort yet"
elif [ ! -z "$SYSTEM_BUILD" ] && [ -d "$SYSTEM_BUILD" ]; then
    print_warn "System build is not supoort yet"
    # Get GSI build
    cd "$SYSTEM_BUILD"
    SYSTEM_REPO_LIST_OUT=$(repo list 2>&1)
    if [[ "$SYSTEM_REPO_LIST_OUT" != "error"* ]]; then
        go_to_repo_root "$PWD"
        if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
            find_repo
        fi
        if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "_arm64" ]]; then
            set_platform_repo "aosp_arm64"
            if [ "$SKIP_BUILD" = false ] ; then
                build_platform
            fi
            SYSTEM_BUILD="${ANDROID_PRODUCT_OUT}/system.img"
        fi
    fi
fi

if [[ "$KERNEL_BUILD" == ab://* ]]; then
    print_info "Download kernel build $KERNEL_BUILD"
    if [ -d "$DOWNLOAD_PATH/gki_dir" ]; then
        rm -rf "$DOWNLOAD_PATH/gki_dir"
    fi
    GKI_DIR="$DOWNLOAD_PATH/gki_dir"
    mkdir -p "$GKI_DIR"
    cd "$GKI_DIR" || $(print_error "Fail to go to $GKI_DIR")
    download_gki_build $KERNEL_BUILD
    KERNEL_BUILD="$GKI_DIR"
elif [ ! -z "$KERNEL_BUILD" ] && [ -d "$KERNEL_BUILD" ]; then
    # Check if kernel repo is provided
    cd "$KERNEL_BUILD"
    KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
    if [[ "$KERNEL_REPO_LIST_OUT" != "error"* ]]; then
        go_to_repo_root "$PWD"
        if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
            find_repo
        fi
        if [ "$SKIP_BUILD" = false ] ; then
            if [ ! -f "common/BUILD.bazel" ]; then
                # TODO: Add build support to android12 and earlier kernels
                print_error "bazel build is not supported in $PWD"
            else
                build_ack
            fi
        fi
        KERNEL_BUILD="$PWD/out/kernel_aarch64/dist"
    fi
fi

if [[ "$VENDOR_KERNEL_BUILD" == ab://* ]]; then
    print_info "Download vendor kernel build $VENDOR_KERNEL_BUILD"
    if [ -d "$DOWNLOAD_PATH/vendor_kernel_dir" ]; then
        rm -rf "$DOWNLOAD_PATH/vendor_kernel_dir"
    fi
    VENDOR_KERNEL_DIR="$DOWNLOAD_PATH/vendor_kernel_dir"
    mkdir -p "$VENDOR_KERNEL_DIR"
    cd "$VENDOR_KERNEL_DIR" || $(print_error "Fail to go to $VENDOR_KERNEL_DIR")
    download_vendor_kernel_build $VENDOR_KERNEL_BUILD
    VENDOR_KERNEL_BUILD="$VENDOR_KERNEL_DIR"
elif [ ! -z "$VENDOR_KERNEL_BUILD" ] && [ -d "$VENDOR_KERNEL_BUILD" ]; then
    # Check if vendor kernel repo is provided
    cd "$VENDOR_KERNEL_BUILD"
    VENDOR_KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
    if [[ "$VENDOR_KERNEL_REPO_LIST_OUT" != "error"* ]]; then
        go_to_repo_root "$PWD"
        if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
            find_repo
        fi
        if [ "$SKIP_BUILD" = false ] ; then
            if [ ! -f "private/google-modules/soc/gs/BUILD.bazel" ]; then
                # TODO: Add build support to android12 and earlier kernels
                print_error "bazel build is not supported in $PWD"
            else
                build_slider
            fi
        fi
        VENDOR_KERNEL_BUILD="$PWD/out/slider/dist"
    fi
fi

cd "$REPO_ROOT_PATH"
if [ -f "${ANDROID_HOST_OUT}/bin/tradefed.sh" ] ; then
    TRADEFED="${ANDROID_HOST_OUT}/bin/tradefed.sh"
    print_info "Use the tradefed from the local built path $TRADEFED"
elif [ -f "$PLATFORM_TF_PREBUILT" ]; then
    TRADEFED="JAVA_HOME=$PLATFORM_JDK_PATH PATH=$PLATFORM_JDK_PATH/bin:$PATH $PLATFORM_TF_PREBUILT"
    print_info "Local Tradefed is not built yet. Use the prebuilt from $PLATFORM_TF_PREBUILT"
elif [ -f "$KERNEL_TF_PREBUILT" ]; then
    TRADEFED="JAVA_HOME=$JDK_PATH PATH=$JDK_PATH/bin:$PATH $KERNEL_TF_PREBUILT"
# No Tradefed found
else
    print_error "Can not find Tradefed binary. Please use flag -tf to specify the binary path."
fi

if [ -z "$PLATFORM_BUILD" ]; then  # No platform build provided
    if [ -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # No kernel or vendor kernel build
        print_info "KERNEL_BUILD=$KERNEL_BUILD VENDOR_KERNEL_BUILD=$VENDOR_KERNEL_BUILD"
        print_error "Nothing to flash"
    elif [ -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # Only vendor kernel build
        print_info "Flash kernel from $VENDOR_KERNEL_BUILD"
        flash_vendor_kernel_build
    elif [ ! -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # Both kernel and vendor kernel builds
        print_error "Mixing only GKI build & vendor kernel build is not supported. Please add platform build."
    elif [ ! -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # Only GKI build
        case "$KERNEL_VERSION" in
            android-mainline)
                if [[ "$DEVICE_KERNEL_STRING" == mainline* ]] && [ ! -z "$SYSTEM_DLKM_VERSION" ]]; then
                    print_info "Device $SERIAL_NUMBER is with android-mainline kernel. Flash GKI directly"
                    flash_gki
                else
                   print_error "Cannot flash android-mainline GKI on $PRODUCT device $SERIAL_NUMBER with $DEVICE_KERNEL_STRING kernel"
                fi
                print_error "Cannot flash android-mainline GKI to device directly"
                ;;
            android14-6.1)
                if [[ "$DEVICE_KERNEL_STRING" == 6.1* && "$DEVICE_KERNEL_STRING" == *android14* && "$SYSTEM_DLKM_VERSION" == "14" ]]; then
                    print_info "Device $SERIAL_NUMBER is with android14-6.1 kernel. Flash GKI directly"
                    flash_gki
                else
                   print_error "Cannot flash android14-6.1 GKI on $PRODUCT device $SERIAL_NUMBER with $DEVICE_KERNEL_STRING kernel"
                fi
                ;;
            android13-5.10)
                flash_gki
                ;;
            *)
                print_error "Unsupported KERNEL_VERSION: $KERNEL_VERSION"
                ;;
        esac
    fi
else  # Platform build provided
    if [ -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # No kernel or vendor kernel build
        print_info "Flash platform build only"
        flash_platform_build
    elif [ -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # Vendor kernel build and platform build
        flash_platform_build
        flash_vendor_kernel_build
    elif [ ! -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then # GKI build and platform build
        print_error "Mixing GKI build & platform build is not supported yet."
    elif [ ! -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # All three builds provided
        print_info "Mix GKI kernel, vendor kernel and platform build"
        mixing_build
        flash_platform_build
    fi
fi