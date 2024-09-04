#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

# fetch_artifact .sh is a handy tool dedicated to download artifacts from ci.
# More info at: go/fetch_artifact,
#    https://android.googlesource.com/tools/fetch_artifact/
# By default Use x20 binary: /google/data/ro/projects/android/fetch_artifact
# Can install fetch_artifact locally with:
# sudo glinux-add-repo android stable && \
# sudo apt update && \
# sudo apt install android-fetch-artifact#
#
FETCH_ARTIFACT=/google/data/ro/projects/android/fetch_artifact

function binary_checker() {
    if ! test -f $FETCH_ARTIFACT; then
        echo -e "\n${RED} $FETCH_ARTIFACT is not found!${END}"
        echo -e "\n${RED} Please check go/fetch_artifact${END} or
        https://android.googlesource.com/tools/fetch_artifact/+/refs/heads/main"
    fi
}

binary_checker
EXTRA_OPTIONS=()
ADD_LATEST=true
ADD_BRANCH=true
ADD_TARGET=true
ADD_OAUTH=true
for i in "$@"; do
    case $i in
        "--bid")
        ADD_LATEST=false
        ;;
        "--branch")
        ADD_BRANCH=false
        ;;
        "--target")
        ADD_TARGET=false
        ;;
        "--use_oau"*)
        ADD_OAUTH=false
        ;;
    esac
done
if $ADD_LATEST; then
    EXTRA_OPTIONS+=" --latest"
fi
if $ADD_BRANCH; then
    EXTRA_OPTIONS+=" --branch git_main"
fi
if $ADD_TARGET; then
    EXTRA_OPTIONS+=" --target aosp_cf_x86_64_phone-trunk_staging-userdebug"
fi
if $ADD_OAUTH; then
    EXTRA_OPTIONS+=" --use_oauth2"
fi
eval "$FETCH_ARTIFACT" "$EXTRA_OPTIONS" "$@"
