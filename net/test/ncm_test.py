#!/usr/bin/python
#
# Copyright 2020 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import cstruct
import csocket
import iproute
import net_test

import ctypes
import fcntl
import os
import struct
import time
import unittest

UsbdevfsBulkTransfer = cstruct.Struct("usbdevfs_bulktransfer", "@IIIP",
                                      "ep len timeout data")
UsbdevfsCtrltransfer = cstruct.Struct(
    "usbdevfs_ctrltransfer", "@BBHHHIP",
    "bRequestType bRequest wValue wIndex wLength timeout data")
UsbdevfsSetinterface = cstruct.Struct("usbdevfs_setinterface", "@II",
                                      "interface altsetting")

UsbDeviceDescriptor = cstruct.Struct(
    "UsbDeviceDescriptor", "@BBHBBBBHHHBBBB",
    ("bLength bDescriptorType bcdUSB bDeviceClass bDeviceSubClass "
     "bDeviceProtocol bMaxPacketSize idVendor idProduct bcdDevice "
     "iManufacturer iProduct iSerialNumber bNumConfigurations"))

UsbCdcNcmNtbParameters = cstruct.Struct(
    "usb_cdc_ncm_ntb_parameters", "=HHIHHHxxIHHHH",
    ("wLength bmNtbFormatsSupported dwNtbInMaxSize wNdpInDivisor "
     "wNdpInPayloadRemainder wNdpInAlignment dwNtbOutMaxSize wNdpOutDivisor "
     "wNdpOutPayloadRemainder wNdpOutAlignment wNtbOutMaxDatagrams"))

BUS = 1
DEV = 2
TIMEOUT = 5000

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2

# For x86_64.
def _IOC(mode, type, nr, size):
  return (
      ((mode & 0x3) << 30)     |  # 2 bits read/write
      ((size & 0x3fff) << 16)  |  # 14 bits size
      (ord(type) << 8) | nr)      # command

def _IO(type, nr):
  return _IOC(_IOC_NONE, type, nr, 0)

def _IOR(type, nr, size):
  return _IOC(_IOC_READ, type, nr, size)

def _IOW(type, nr, size):
  return _IOC(_IOC_WRITE, type, nr, size)

def _IOWR(type, nr, size):
  return _IOC(_IOC_WRITE | _IOC_READ, type, nr, size)

USBDEVFS_CONTROL = _IOWR("U", 0, len(UsbdevfsCtrltransfer))
USBDEVFS_SETINTERFACE = _IOR('U', 4, len(UsbdevfsSetinterface))
USBDEVFS_CLAIMINTERFACE = _IOR('U', 15, 4)
USBDEVFS_SETCONFIGURATION = _IOR('U', 5, 4)
USBDEVFS_GET_SPEED = _IO("U", 31)

USB_DIR_OUT = 0
USB_DIR_IN  = 0x80

USB_TYPE_STANDARD = 0 << 5
USB_TYPE_CLASS    = 1 << 5
USB_TYPE_VENDOR   = 2 << 5

USB_RECIP_DEVICE    = 0
USB_RECIP_INTERFACE = 1
USB_RECIP_ENDPOINT  = 2
USB_RECIP_OTHER     = 3

USB_CDC_GET_NTB_PARAMETERS = 0x80
USB_CDC_GET_NET_ADDRESS    = 0x81
USB_CDC_SET_CRC_MODE       = 0x8a

USB_REQ_GET_STATUS        = 0x00
USB_REQ_CLEAR_FEATURE     = 0x01
USB_REQ_SET_FEATURE       = 0x03
USB_REQ_SET_ADDRESS       = 0x05
USB_REQ_GET_DESCRIPTOR    = 0x06
USB_REQ_SET_DESCRIPTOR    = 0x07
USB_REQ_GET_CONFIGURATION = 0x08
USB_REQ_SET_CONFIGURATION = 0x09
USB_REQ_GET_INTERFACE     = 0x0A
USB_REQ_SET_INTERFACE     = 0x0B
USB_REQ_SYNCH_FRAME       = 0x0C
USB_REQ_SET_SEL           = 0x30
USB_REQ_SET_ISOCH_DELAY   = 0x31

_TEST_VID = 0x1a0a  # USB-IF non-workshop
_TEST_PID = 0xbadd  # USB OTG Compliance test device

class UsbGadget(object):
  _CONFIGFS_PATH = "/tmp/config/usb_gadget"
  _FAKE_UDC = "dummy_udc.0"

  def _Path(self, path_elements):
    return os.path.join(self.path, *path_elements)

  def SetProp(self, path_elements, value):
    open(self._Path(path_elements), "w").write(value)

  def SetGadgetProp(self, prop, value):
    self.SetProp([prop], value)

  def AddElement(self, type, value):
    elementlist = getattr(self, type)
    path = self._Path([type, value])
    os.mkdir(path)
    elementlist.append(value)

  def RemoveElement(self, type, value):
    elementlist = getattr(self, type)
    path = self._Path([type, value])
    os.rmdir(path)
    elementlist.remove(value)

  def AddFunction(self, name):
    self.AddElement("functions", name)

  def RemoveFunction(self, name):
    self.RemoveElement("functions", name)

  def AddConfig(self, name):
    self.AddElement("configs", name)

  def RemoveConfig(self, name):
    self.RemoveElement("configs", name)

  def EnableFunction(self, config, function):
    target = self._Path(["functions", function])
    config_symlink = self._Path(["configs", config, function])
    os.symlink(target, config_symlink)
    self.enabled.append((config, function))

  def DisableFunction(self, config, function):
    config_symlink = self._Path(["configs", config, function])
    os.unlink(config_symlink)
    self.enabled.remove((config, function))

  def Disconnect(self):
    self.Disable()
    for config, function in self.enabled:
      self.DisableFunction(config, function)
    for function in self.functions:
      self.RemoveFunction(function)
    for config in self.configs:
      self.RemoveConfig(config)
    os.rmdir(self.path)

  def SetVidPid(self, vid, pid):
    self.SetGadgetProp("idVendor", "%d" % vid)
    self.SetGadgetProp("idProduct", "%d" % pid)

  def Enable(self):
    self.SetGadgetProp("UDC", self._FAKE_UDC)

  def Disable(self):
    self.SetGadgetProp("UDC", "")

  def __init__(self, name):
    self.name = name
    self.path = os.path.join(self._CONFIGFS_PATH, name)
    self.functions = []
    self.configs = []
    self.enabled = []
    if (os.access(self.path, os.F_OK)):
      self.Disconnect()
    os.mkdir(self.path)


class UsbDevice(object):

  _PATH = "/dev/bus/usb"

  @classmethod
  def FindByVidPid(cls, vid, pid):
    for dirpath, dirnames, filenames in os.walk(cls._PATH):
      for filename in filenames:
        path = os.path.join(dirpath, filename)
        data = open(path, "r").read(len(UsbDeviceDescriptor))
        if len(data) < len(UsbDeviceDescriptor):
          continue
        d = UsbDeviceDescriptor(data)
        if d.idVendor == vid and d.idProduct == pid:
          bus = int(os.path.basename(dirpath))
          device = int(filename)
          return bus, device
    raise KeyError("No device with VID %x PID %x" % (vid, pid))

  def __init__(self, bus, device):
    path = os.path.join(self._PATH, "%03d" % bus, "%03d" % device)
    self.fd = open(path, "w")

  def GetSpeed(self):
    return fcntl.ioctl(self.fd, USBDEVFS_GET_SPEED)

  def _U32Ioctl(self, cmd, num):
    num = struct.pack("@I", num)
    fcntl.ioctl(self.fd, cmd, num)

  def ClaimInterface(self, num):
    self._U32Ioctl(USBDEVFS_CLAIMINTERFACE, num)

  def SetConfiguration(self, num):
    self._U32Ioctl(USBDEVFS_SETCONFIGURATION, num)

  def SetInterface(self, interface, altsetting):
    fcntl.ioctl(self.fd, USBDEVFS_SETINTERFACE,
                UsbdevfsSetinterface((interface, altsetting)).Pack())

  def CtrlTransfer(self, reqtype, request, value, index, data):
    if data is not None:
      data_buf = ctypes.create_string_buffer(data)
      data_ptr = ctypes.addressof(data_buf)
      data_len = len(data)
    else:
      data_ptr = 0
      data_len = 0

    t = UsbdevfsCtrltransfer((reqtype, request, value, index, data_len,
                              TIMEOUT, data_ptr))
    fcntl.ioctl(self.fd, USBDEVFS_CONTROL, t.Pack())

    if data is None:
      return None

    return data_buf.raw


class NcmTest(net_test.NetworkTest):

  @classmethod
  def setUpClass(cls):
    cls.gadget = UsbGadget("g.1")
    cls.gadget.AddFunction("ncm.ncm42")
    cls.gadget.AddConfig("c.1")
    cls.gadget.EnableFunction("c.1", "ncm.ncm42")
    cls.gadget.SetVidPid(_TEST_VID, _TEST_PID)
    cls.gadget.Enable()

    cls.iproute = iproute.IPRoute()    

  @classmethod
  def tearDownClass(cls):
    cls.gadget.Disconnect()

  def testNcmInit(self):
    time.sleep(1)
    bus, device = UsbDevice.FindByVidPid(_TEST_VID, _TEST_PID)
    d = UsbDevice(bus, device)
    d.SetConfiguration(1)

    iface = 0
    d.ClaimInterface(iface)

    # Get NTB parameters.
    reqtype = USB_TYPE_CLASS | USB_DIR_IN | USB_RECIP_INTERFACE
    request = USB_CDC_GET_NTB_PARAMETERS
    data = UsbCdcNcmNtbParameters().Pack()
    data = d.CtrlTransfer(reqtype, request, 0, iface, data)
    params = UsbCdcNcmNtbParameters(data)

    self.assertEquals(28, params.wLength)
    self.assertTrue(params.bmNtbFormatsSupported & 0x1 == 1)

    # Disable CRC.
    reqtype = USB_TYPE_CLASS | USB_DIR_OUT | USB_RECIP_INTERFACE
    request = USB_CDC_SET_CRC_MODE
    value = 0  # No CRC.
    data = d.CtrlTransfer(reqtype, request, value, iface, None)

    iface = 1
    d.ClaimInterface(iface)
    d.SetInterface(iface, 1)
    time.sleep(1)

if __name__ == "__main__":
  unittest.main()
