/*
 * Copyright (C) 2018 The Android Open Source Project
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

/* This tool shims the kernel net tests' Debian filesystem image to enable
 * the initramfs to be mounted under /host, so the same filesystem can be
 * used for UML and QEMU. It also handles 'ro', 'init=<cmd>' or
 * 'root=<blkdev>' on the kernel cmdline.
 *
 * As the /sbin/net_test.sh script unfortunately calls out to 'halt' instead
 * of 'poweroff', and QEMU does not consider 'halt' to be a shutdown (and UML
 * does), the tool patches the root filesystem to work around this problem.
 * (This patching does not occur in read-only mode, so things will break.)
 */

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// Taken from android::base

#define CHECK_NE(a, b) \
    if ((a) == (b))    \
        abort();

static std::vector<std::string> Split(const std::string& s,
                                      const std::string& delimiters) {
    CHECK_NE(delimiters.size(), 0U);

    std::vector<std::string> result;

    size_t base = 0;
    size_t found;
    while (true) {
        found = s.find_first_of(delimiters, base);
        result.push_back(s.substr(base, found - base));
        if (found == s.npos)
            break;
        base = found + 1;
    }

    return result;
}

static std::string Trim(const std::string& s) {
    std::string result;

    if (s.size() == 0) {
        return result;
    }

    size_t start_index = 0;
    size_t end_index = s.size() - 1;

    // Skip initial whitespace.
    while (start_index < s.size()) {
        if (!isspace(s[start_index])) {
            break;
        }
        start_index++;
    }

    // Skip terminating whitespace.
    while (end_index >= start_index) {
        if (!isspace(s[end_index])) {
            break;
        }
        end_index--;
    }

    // All spaces, no beef.
    if (end_index < start_index) {
        return "";
    }
    // Start_index is the first non-space, end_index is the last one.
    return s.substr(start_index, end_index - start_index + 1);
}

static bool ReadFdToString(int fd, std::string* content) {
    content->clear();
    char buf[BUFSIZ];
    ssize_t n;
    while ((n = TEMP_FAILURE_RETRY(read(fd, &buf[0], sizeof(buf)))) > 0) {
        content->append(buf, n);
    }
    return (n == 0) ? true : false;
}

static bool ReadFileToString(const std::string& path, std::string* content,
                             bool follow_symlinks) {
    int flags = O_RDONLY | O_CLOEXEC | (follow_symlinks ? 0 : O_NOFOLLOW);
    int fd = TEMP_FAILURE_RETRY(open(path.c_str(), flags));
    if (fd == -1) {
        return false;
    }
    bool result = ReadFdToString(fd, content);
    close(fd);
    return result;
}

// End taken from android::base

#define TRY(x, errmsg)      \
    if (x) {                \
        int errnum = errno; \
        perror(errmsg);     \
        return -errnum;     \
    }

int main(void) {
    // Mount /proc so we can access the kernel cmdline
    TRY(mkdir("/proc", 0755), "mkdir /proc");
    TRY(mount(NULL, "/proc", "proc", 0, NULL), "mount /proc");

    // Open /proc/cmdline, read its contents, and close it
    std::string cmdline;
    TRY(!ReadFileToString("/proc/cmdline", &cmdline, false), "read cmdline");

    // We are done with /proc now
    TRY(umount("/proc"), "umount /proc");
    TRY(rmdir("/proc"), "rmdir /proc");

    // Tokenize the cmdline to find init=, root=, ro
    std::string root("/dev/vda");
    bool ro = false;
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>("/sbin/init"));
    argv.push_back(NULL);
    for (const auto& entry : Split(Trim(cmdline), " ")) {
        std::vector<std::string> pieces = Split(entry, "=");
        if (pieces.size() == 2) {
            if (pieces[0] == "root") {
                root = pieces[1];
            } else if (pieces[0] == "init") {
                argv[0] = new char[pieces[1].length() + 1];
                std::strcpy(argv[0], pieces[1].c_str());
            }
        } else {
            if (entry == "ro") {
                ro = true;
            } else if (entry == "rw") {
                ro = false;
            }
        }
    }

    // Mount /dev so we can find the new rootfs
    TRY(mount(NULL, "/dev", "devtmpfs", 0, NULL), "mount /dev");

    // Mount the new rootfs; filesystem type is assumed to be ext4
    if (ro) {
        TRY(mount(root.c_str(), "/root", "ext4", MS_RDONLY, NULL),
            "mount /root ro");
    } else {
        TRY(mount(root.c_str(), "/root", "ext4", 0, NULL), "mount /root");
        unlink("/root/usr/local/sbin/halt");
        TRY(symlink("/host/halt-qemu.sh", "/root/usr/local/sbin/halt"),
            "symlink /usr/local/sbin/halt");
    }

    // The tests need /dev in the new rootfs, so move it there
    TRY(mount("/dev", "/root/dev", NULL, MS_MOVE, NULL), "mount /root/dev");

    // Bind mount the initramfs to /host under the new rootfs
    TRY(mount("/", "/root/host", NULL, MS_BIND, NULL), "mount /root/host");

    // Make the new rootfs /
    TRY(chdir("/root"), "chdir /root");
    TRY(mount("/root", "/", NULL, MS_MOVE, NULL), "mount /");
    TRY(chroot("."), "chroot .");
    TRY(chdir("/"), "chdir /");

    // Tidy up the old rootfs mountpoint
    TRY(rmdir("/host/root"), "rmdir /host/root");

    // Start the new init
    TRY(execv(argv[0], argv.data()), "execv init");

    return 0;
}
