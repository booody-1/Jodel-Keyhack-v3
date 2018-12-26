import subprocess
import re
from typing import Dict, List

import os


class Aapt:
    """
    Parser for the Android Asset Packaging Tool (aapt).
    """

    __AAPT_EXEC_PATH = os.path.join("files", "aapt", "aapt.exe")
    __LABEL_APP_NAME = "application-label:"
    __LABEL_PACKAGE_NAME = "package:(?:.*) name="
    __LABEL_PACKAGE_VERSION_CODE = "package:(?:.*) versionCode="
    __LABEL_PACKAGE_VERSION_NAME = "package:(?:.*) versionName="
    __LABEL_SDK_MAX_VERSION = "maxSdkVersion:"
    __LABEL_SDK_MIN_VERSION = "sdkVersion:"
    __LABEL_SDK_TARGET_VERSION = "targetSdkVersion:"
    __LABEL_PERMISSION_NAME = "uses-permission: name="

    def __init__(self):
        pass

    @staticmethod
    def _extract_string_pattern(string: str, pattern: str) -> str:
        """
        Extract the value of a given pattern from a given string.
        :param string: The string to be searched.
        :param pattern: The pattern to extract.
        :return: The extracted pattern if any is found, an empty string otherwise.
        """
        match = re.search(pattern, string, re.MULTILINE | re.IGNORECASE)
        if match and match.group(1):
            return match.group(1).strip()
        else:
            return ""

    @staticmethod
    def _find_between(s: str, prefix: str, suffix: str) -> str:
        """
        Find a substring in a string, starting after a specified prefix and ended before a specified suffix.
        :param s: The string.
        :param prefix: The prefix of the file name to be deleted.
        :param suffix: The suffix of the file name to be deleted.
        :return: The substring starting after prefix and ended before suffix.
        """
        try:
            start = s.index(prefix) + len(prefix)
            end = s.index(suffix, start)
            return s[start:end]
        except ValueError:
            return ""

    @staticmethod
    def _find_all(haystack: str, needle: str) -> str:
        """
        Find all the substring starting position in a string.
        :param haystack: The string.
        :param needle: The substring to be found.
        :return: The substring starting after prefix and ended before suffix.
        """
        offs = -1
        while True:
            offs = haystack.find(needle, offs + 1)
            if offs == -1:
                break
            else:
                yield offs

    @classmethod
    def _dump_badging(cls, filepath: str) -> str:
        """
        Retrieve the aapt dump badging.
        :param filepath: The APK package file path.
        :return: The APK dump badging.
        """
        command = Aapt.__AAPT_EXEC_PATH + " dump badging " + filepath
        return Aapt._launch_shell_command_and_get_result(command)

    @classmethod
    def _dump_permissions(cls, filepath: str) -> str:
        """
        Retrieve the aapt dump permissions.
        :param filepath: The APK package file path.
        :return: The APK dump badging.
        """
        command = Aapt.__AAPT_EXEC_PATH + " dump permissions " + filepath
        return Aapt._launch_shell_command_and_get_result(command)

    @classmethod
    def _dump_manifest_xmltree(cls, filepath: str) -> str:
        """
        Dump the XML tree of the AndroidManifest.xml file of a given APK package.
        :param filepath: The APK package file path.
        :return: The XML tree.
        """
        command = Aapt.__AAPT_EXEC_PATH + " dump xmltree " + filepath + " AndroidManifest.xml"
        return Aapt._launch_shell_command_and_get_result(command)

    @classmethod
    def _launch_shell_command_and_get_result(cls, command: str) -> str:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
        return process.communicate()[0].decode("utf-8")

    @classmethod
    def get_app_name(cls, filepath: str) -> str:
        """
        Retrieve the app name of an APK package.
        :param filepath: The APK package file path.
        :return: The app name.
        """
        apk_app_pattern = "^" + Aapt.__LABEL_APP_NAME + "'(.+)'$"
        return Aapt._extract_string_pattern(cls._dump_badging(filepath), apk_app_pattern)

    @classmethod
    def get_apk_info(cls, filepath: str) -> Dict:
        """
        Retrieve the APK info.
        :param filepath: The APK package file path.
        :return: The APK info as a dictionary (i.e.
                 {
                    "package_name": "...",
                    "version": {"code":1, "name":"1.0"},
                    "sdk": {"target": "...", max: "...", min: "..."}
                }).
        """
        info = cls._dump_badging(filepath)

        apk_package_name_pattern = "^" + cls.__LABEL_PACKAGE_NAME + "'([a-zA-Z0-9\-\.]+)'"
        apk_version_name_pattern = "^" + cls.__LABEL_PACKAGE_VERSION_NAME + "'([a-zA-Z0-9_\-\.]+)'"

        apk = {
            "package_name": cls._extract_string_pattern(info, apk_package_name_pattern),
            "version": {
                "code": "",
                "name": cls._extract_string_pattern(info, apk_version_name_pattern),
            },
            "sdk": {},
        }

        try:
            apk_version_code_pattern = "^" + cls.__LABEL_PACKAGE_VERSION_CODE + "'([0-9\.]+)'"
            apk["version"]["code"] = int(cls._extract_string_pattern(info, apk_version_code_pattern))
        except ValueError:
            pass

        apk_sdk_target_pattern = "^" + cls.__LABEL_SDK_TARGET_VERSION + "'(.+)'"
        sdk = cls._extract_string_pattern(info, apk_sdk_target_pattern)
        if sdk != "":
            apk["sdk"]["target"] = sdk

        apk_sdk_max_pattern = "^" + cls.__LABEL_SDK_MAX_VERSION + "'(.+)'"
        sdk = cls._extract_string_pattern(info, apk_sdk_max_pattern)
        if sdk != "":
            apk["sdk"]["max"] = sdk

        apk_sdk_min_pattern = "^" + cls.__LABEL_SDK_MIN_VERSION + "'(.+)'"
        sdk = Aapt._extract_string_pattern(info, apk_sdk_min_pattern)
        if sdk != "":
            apk["sdk"]["min"] = sdk

        return apk

    @classmethod
    def get_manifest_info(cls, filepath: str) -> Dict:
        """
        Retrieve the AndroidManifest.xml info.
        :param filepath: The APK package file path.
        :return: The list of Activities, Services and BroadcastReceivers as a dictionary.
        """
        activities = []  # type: List[Dict[str, str]]
        services = []  # type: List[Dict[str, str]]
        receivers = []  # type: List[Dict[str, str]]

        xmltree = cls._dump_manifest_xmltree(filepath)
        # @TODO: Refactor this code...
        try:
            # Extract only from the <application> tag:
            xmltree = xmltree[xmltree.index("application"):-1]

            for offs in cls._find_all(xmltree, "activity"):
                activity = xmltree[offs:-1]
                idx = cls._find_between(activity, "android:name(", ")=\"")
                activities.append({"name": cls._find_between(activity, "android:name(" + idx + ")=\"", "\"")})

            for offs in cls._find_all(xmltree, "service"):
                service = xmltree[offs:-1]
                idx = cls._find_between(service, "android:name(", ")=\"")
                services.append({"name": cls._find_between(service, "android:name(" + idx + ")=\"", "\"")})

            for offs in cls._find_all(xmltree, "receiver"):
                receiver = xmltree[offs:-1]
                idx = cls._find_between(receiver, "android:name(", ")=\"")
                receivers.append({"name": cls._find_between(receiver, "android:name(" + idx + ")=\"", "\"")})
        except ValueError:
            # The <application> TAG has not been found...
            pass

        return {
            "activities": activities,
            "services": services,
            "receivers": receivers,
        }

    @classmethod
    def get_app_permissions(cls, filepath: str) -> List:
        """
        Retrieve the permissions from the AndroidManifest.xml file of a given APK package.
        :param filepath: The APK package file path.
        :return: The list of required permissions.
        """
        dump = cls._dump_permissions(filepath).splitlines()

        permissions = []
        for line in dump:
            apk_permission_name_pattern = "^" + Aapt.__LABEL_PERMISSION_NAME + "'(.*)'$"
            perm = Aapt._extract_string_pattern(line, apk_permission_name_pattern)
            if perm != "":
                permissions.append(perm)
        permissions.sort()

        return permissions

