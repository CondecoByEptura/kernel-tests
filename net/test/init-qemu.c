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

/* For TEMP_FAILURE_RETRY */
#define _GNU_SOURCE

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TRY(x, errmsg) \
	if (x) { \
		perror(errmsg); \
		return -errno; \
	}

#define DELIMS " = \n"
#define NEXT_TOKEN(token, name, var, offset, max) \
	if (strcmp(token, name) == 0) { \
		token += sizeof(name); \
		if (offset > max) \
			break; \
		var = token; \
	}

int main(void)
{
	long int n, offset = 0, size = BUFSIZ;
	char *init[] = { "/sbin/init", NULL };
	char buf[BUFSIZ] = { 0 }, *token;
	char *root = "/dev/vda";
	int fd, ro = 0;

	/* Mount /proc so we can access the kernel cmdline */
	TRY(mkdir("/proc", 0755), "mkdir /proc");
	TRY(mount(NULL, "/proc", "proc", 0, NULL), "mount /proc");

	/* Open /proc/cmdline and read its contents into buf */
	fd = TEMP_FAILURE_RETRY(open("/proc/cmdline", O_RDONLY | O_CLOEXEC));
	TRY(fd < 0, "open cmdline");
	while ((n = TEMP_FAILURE_RETRY(read(fd, &buf[offset], size))) > 0) {
		offset += n;
		size -= n;
	}
	TRY(close(fd), "close cmdline");
	TRY(n < 0, "read cmdline");

	/* We are done with /proc now */
	TRY(umount("/proc"), "umount /proc");
	TRY(rmdir("/proc"), "rmdir /proc");

	/* Tokenize the buffer to find init=, root= */
	size = strlen(buf);
	token = strtok(buf, DELIMS);
	if (size && token) {
		do {
			offset = token - buf;
			NEXT_TOKEN(token, "init", init[0], offset, size);
			NEXT_TOKEN(token, "root", root, offset, size);
			if (strcmp(token, "ro") == 0) {
				ro = 1;
			}
		} while ((token = strtok(NULL, DELIMS)));
	}

	/* Mount /dev so we can find the new rootfs */
	TRY(mount(NULL, "/dev", "devtmpfs", 0, NULL), "mount /dev");

	/* Mount the new rootfs; filesystem type is assumed to be ext4 */
	if (ro) {
		TRY(mount(root, "/root", "ext4", MS_RDONLY, NULL),
			  "mount /root ro");
	} else {
		TRY(mount(root, "/root", "ext4", 0, NULL), "mount /root");
		unlink("/root/usr/local/sbin/halt");
		TRY(symlink("/host/halt-qemu.sh", "/root/usr/local/sbin/halt"),
			   "symlink /usr/local/sbin/halt");
	}

	/* The tests need /dev in the new rootfs, so move it there */
	TRY(mount("/dev", "/root/dev", NULL, MS_MOVE, NULL),
		  "mount /root/dev");

	/* Bind mount the initramfs to /host under the new rootfs */
	TRY(mount("/", "/root/host", NULL, MS_BIND, NULL), "mount /root/host");

	/* Make the new rootfs / */
	TRY(chdir("/root"), "chdir /root");
	TRY(mount("/root", "/", NULL, MS_MOVE, NULL), "mount /");
	TRY(chroot("."), "chroot .");
	TRY(chdir("/"), "chdir /");

	/* Tidy up the old rootfs mountpoint */
	TRY(rmdir("/host/root"), "rmdir /host/root");

	/* Start the new init */
	TRY (execv(init[0], init), "execv init");

	return 0;
}
