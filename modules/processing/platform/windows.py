# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import datetime

from lib.cuckoo.common.abstracts import BehaviorHandler
from lib.cuckoo.common.netlog import BsonParser

log = logging.getLogger(__name__)

def NT_SUCCESS(value):
    return value % 2**32 < 0x80000000

class WindowsBehaviorSummary(BehaviorHandler):
    """Constructs a summary of the behavior API logs."""
    key = "summary"
    event_types = ["apicall"]

    def __init__(self, *args, **kwargs):
        super(WindowsBehaviorSummary, self).__init__(*args, **kwargs)
        self.files = {}
        self.behavior = {}

    def handle_event(self, call):
        self.process_call(call["api"], call["return_value"],
                          call["arguments"])

    def run(self):
        self.finish()
        return self.results()

    def process_call(self, apiname, return_value, arguments):
        fn = getattr(self, "_api_%s" % apiname, None)
        if fn is not None:
            fn(return_value, arguments)

    def report(self, category, arg=None, **kwargs):
        if category not in self.behavior:
            self.behavior[category] = []

        if arg and kwargs:
            raise Exception("Can't have both args and kwargs!")

        value = arg or kwargs
        if value and value not in self.behavior[category]:
            self.behavior[category].append(value)

    def finish(self):
        for f in self.files.values():
            self._report_file(f)

    def results(self):
        return self.behavior

    def _report_file(self, f):
        if f["read"]:
            self.report("file_read", f["filepath"])

        if f["written"]:
            self.report("file_written", f["filepath"])

    # Generic file & directory stuff.

    def _api_CreateDirectoryW(self, return_value, arguments):
        self.report("directory_created", arguments["dirpath"])

    _api_CreateDirectoryExW = _api_CreateDirectoryW

    def _api_RemoveDirectoryA(self, return_value, arguments):
        self.report("directory_removed", arguments["dirpath"])

    _api_RemoveDirectoryW = _api_RemoveDirectoryA

    def _api_MoveFileWithProgressW(self, return_value, arguments):
        self.report("file_moved",
                    src=arguments["oldfilepath"],
                    dst=arguments["newfilepath"])

    def _api_CopyFileA(self, return_value, arguments):
        self.report("file_copied",
                    src=arguments["oldfilepath"],
                    dst=arguments["newfilepath"])

    _api_CopyFileW = _api_CopyFileA
    _api_CopyFileExW = _api_CopyFileA

    def _api_DeleteFileA(self, return_value, arguments):
        self.report("file_deleted", arguments["filepath"])

    _api_DeleteFileW = _api_DeleteFileA
    _api_NtDeleteFile = _api_DeleteFileA

    def _api_FindFirstFileExA(self, return_value, arguments):
        self.report("directory_enumerated", arguments["filepath"])

    _api_FindFirstFileExW = _api_FindFirstFileExA

    # File stuff.

    def _api_NtCreateFile(self, return_value, arguments):
        if NT_SUCCESS(return_value):
            self.files[arguments["file_handle"]] = {
                "read": False,
                "written": False,
                "filepath": arguments["filepath"],
            }

        self.report("file_opened", arguments["filepath"])

    _api_NtOpenFile = _api_NtCreateFile

    def _api_NtReadFile(self, return_value, arguments):
        h = arguments["file_handle"]
        if NT_SUCCESS(return_value) and h in self.files:
            self.files[h]["read"] = True

    def _api_NtWriteFile(self, return_value, arguments):
        h = arguments["file_handle"]
        if NT_SUCCESS(return_value) and h in self.files:
            self.files[h]["written"] = True

    # Registry stuff.

    def _api_RegOpenKeyExA(self, return_value, arguments):
        self.report("regkey_opened", arguments["regkey"])

    _api_RegOpenKeyExW = _api_RegOpenKeyExA
    _api_RegCreateKeyExA = _api_RegOpenKeyExA
    _api_RegCreateKeyExW = _api_RegOpenKeyExA

    def _api_RegDeleteKeyA(self, return_value, arguments):
        self.report("regkey_deleted", arguments["regkey"])

    _api_RegDeleteKeyW = _api_RegDeleteKeyA
    _api_RegDeleteValueA = _api_RegDeleteKeyA
    _api_RegDeleteValueW = _api_RegDeleteKeyA
    _api_NtDeleteValueKey = _api_RegDeleteKeyA

    def _api_RegQueryValueExA(self, return_value, arguments):
        self.report("regkey_read", arguments["regkey"])

    _api_RegQueryValueExW = _api_RegQueryValueExA
    _api_NtQueryValueKey = _api_RegQueryValueExA

    def _api_RegSetValueExA(self, return_value, arguments):
        self.report("regkey_written", arguments["regkey"])

    _api_RegSetValueExW = _api_RegSetValueExA
    _api_NtSetValueKey = _api_RegSetValueExA

    def _api_NtClose(self, return_value, arguments):
        h = arguments["handle"]
        if h in self.files:
            self._report_file(self.files[h])
            del self.files[h]

    def _api_RegCloseKey(self, return_value, arguments):
        args = dict(handle=arguments["key_handle"])
        return self._api_NtClose(return_value, args)

    # Network stuff.

    def _api_URLDownloadToFileW(self, return_value, arguments):
        self.report("downloads_file", arguments["url"])
        self.report("file_written", arguments["filepath"])

    def _api_InternetConnectA(self, return_value, arguments):
        self.report("connects_host", arguments["hostname"])

    _api_InternetConnectW = _api_InternetConnectA

    def _api_InternetOpenUrlA(self, return_value, arguments):
        self.report("fetches_url", arguments["url"])

    _api_InternetOpenUrlW = _api_InternetOpenUrlA

    def _api_DnsQuery_A(self, return_value, arguments):
        if arguments["hostname"]:
            self.report("resolves_host", arguments["hostname"])

    _api_DnsQuery_W = _api_DnsQuery_A
    _api_DnsQuery_UTF8 = _api_DnsQuery_A
    _api_getaddrinfo = _api_DnsQuery_A
    _api_GetAddrInfoW = _api_DnsQuery_A
    _api_gethostbyname = _api_DnsQuery_A

    def _api_connect(self, return_value, arguments):
        self.report("connects_ip", arguments["ip_address"])

    # Mutex stuff
    def _api_NtCreateMutant(self, return_value, arguments):
        self.report("mutex", arguments["mutant_name"])

    _api_ConnectEx = _api_connect

class WindowsApiStats(BehaviorHandler):
    """Collects API statistics."""
    key = "apistats"
    event_types = ["process", "apicall"]

    def __init__(self, *args, **kwargs):
        super(WindowsApiStats, self).__init__(*args, **kwargs)
        self.apistats = {}
        self.curstats = None

    def handle_process_event(self, process):
        pid = "%d" % process["pid"]
        self.curstats = self.apistats[pid] = {}

    def handle_apicall_event(self, call):
        apiname = call["api"]
        self.curstats[apiname] = self.curstats.get(apiname, 0) + 1

    def run(self):
        return self.apistats

class MonitorProcessLog(list):
    def __init__(self, eventstream):
        self.eventstream = eventstream
        self.first_seen = None

    def __iter__(self):
        for event in self.eventstream:
            if event["type"] == "process":
                self.first_seen = event["first_seen"]
            elif event["type"] == "apicall":
                event["time"] = self.first_seen + datetime.timedelta(0, 0, event["time"] * 1000)

                del event["type"]
                yield event

    def __nonzero__(self):
        return True

class WindowsMonitor(BehaviorHandler):
    """Parses monitor generated logs."""
    key = "platform"

    def __init__(self, *args, **kwargs):
        super(WindowsMonitor, self).__init__(*args, **kwargs)
        self.results = {
            "name": "windows",
            "architecture": "unknown", # look this up in the task / vm info?
            "source": ["monitor", "windows"],
            "processes": [],
        }
        self.matched = False

    def handles_path(self, path):
        if path.endswith(".bson"):
            self.matched = True
            return True

    def parse(self, path):
        # Invoke parsing of current log file.
        parser = BsonParser(open(path, "rb"))

        for event in parser:
            if event["type"] == "process":
                process = dict(event)
                process["calls"] = MonitorProcessLog(parser)
                self.results["processes"].append(process)

            yield event

    def run(self):
        if not self.matched:
            return

        self.results["processes"].sort(key=lambda process: process["first_seen"])
        return self.results
