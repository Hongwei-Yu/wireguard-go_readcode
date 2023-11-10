//go:build linux || darwin || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const (
	IpcErrorIO        = -int64(unix.EIO)
	IpcErrorProtocol  = -int64(unix.EPROTO)
	IpcErrorInvalid   = -int64(unix.EINVAL)
	IpcErrorPortInUse = -int64(unix.EADDRINUSE)
	IpcErrorUnknown   = -55 // ENOANO
)

// socketDirectory is variable because it is modified by a linker
// flag in wireguard-android.
var socketDirectory = "/var/run/wireguard"

func sockPath(iface string) string {
	return fmt.Sprintf("%s/%s.sock", socketDirectory, iface)
}

func UAPIOpen(name string) (*os.File, error) {
	// 创建/var/run/wireguard文件夹
	if err := os.MkdirAll(socketDirectory, 0o755); err != nil {
		return nil, err
	}
	// /var/run/wireguard/name.sock
	socketPath := sockPath(name)
	//&UnixAddr{/var/run/wireguard/name.sock,unix}
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, err
	}
	// 赋予077权限 077代表着这个文件的所属者没有任何权限，所属组有所有权限（读，写，执行），其他用户有所有权限（读，写，执行）
	oldUmask := unix.Umask(0o077)
	defer unix.Umask(oldUmask)
	//ListenUnix acts like Listen for Unix networks.
	//The network must be "unix" or "unixpacket".
	listener, err := net.ListenUnix("unix", addr)
	if err == nil {
		return listener.File()
	}

	// Test socket, if not in use cleanup and try again.
	if _, err := net.Dial("unix", socketPath); err == nil {
		return nil, errors.New("unix socket in use")
	}
	if err := os.Remove(socketPath); err != nil {
		return nil, err
	}
	listener, err = net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	return listener.File()
}
