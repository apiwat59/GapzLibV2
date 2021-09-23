﻿using LoggerLibrary;
using LoggerLibrary.Interfaces;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace WindowsHelpers
{
    public class PageFileHelper
    {
        private readonly ISimpleLogger _logFile;
        public static List<PageFile> PageFiles = new();

        public PageFileHelper(ISimpleLogger logFile)
        {
            _logFile = logFile;
            ReadConfig();
        }

        public bool ReadConfig()
        {
            try
            {
                PageFiles = new List<PageFile>();

                // ******************************
                // Index Page Files by Fixed-Disk Drives.
                // ******************************Z

                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    if (d.DriveType.ToString().ToLower().Equals("fixed"))
                    {
                        PageFile p = new();
                        p.Name = "<No page file>";
                        p.DriveLetter = d.Name.ToUpper();
                        p.Comment = "No page file";
                        p.AutomaticManagement = false;
                        p.InitialSize = 0;
                        p.MaximumSize = 0;
                        p.AllocatedBaseSize = 0;
                        p.CurrentUsage = 0;
                        p.PeakUsage = 0;
                        p.AvailableSpace = d.TotalFreeSpace / 1048576; // 1MB = 1,048,576 bytes.

                        PageFiles.Add(p);
                    }
                }

                // ******************************
                // Query PageFile Usage Stats by Disk Drive.
                // ******************************

                ManagementScope scope = new(@"\\.\root\cimv2");
                scope.Connect();
                ManagementObjectSearcher searcher = new("SELECT * FROM Win32_PageFileUsage");

                foreach (ManagementBaseObject obj in searcher.Get())
                {
                    string driveLetter = obj["Name"].ToString().ToUpper().Substring(0, 3);

                    foreach (PageFile pf in PageFiles)
                    {
                        if (pf.DriveLetter.ToUpper().Equals(driveLetter.ToUpper()))
                        {
                            pf.Name = obj["Name"].ToString();
                            pf.AllocatedBaseSize = int.Parse(obj["AllocatedBaseSize"].ToString());
                            pf.CurrentUsage = int.Parse(obj["CurrentUsage"].ToString());
                            pf.PeakUsage = int.Parse(obj["PeakUsage"].ToString());

                            // ******************************
                            // Query PageFile Settings by Drive.
                            // ******************************

                            ObjectQuery settingsQuery = new("SELECT * FROM Win32_PageFileSetting");
                            ManagementObjectSearcher innerSearcher = new(scope, settingsQuery);
                            ManagementObjectCollection queryCollection = innerSearcher.Get();

                            foreach (ManagementObject m in queryCollection)
                            {
                                if (m["Name"].ToString().ToUpper().Equals(pf.Name.ToUpper()))
                                {
                                    pf.InitialSize = int.Parse(m["InitialSize"].ToString());
                                    pf.MaximumSize = int.Parse(m["MaximumSize"].ToString());

                                    if (pf.MaximumSize == 0 && pf.InitialSize == pf.MaximumSize)
                                    {
                                        pf.Comment = "System Managed [Dynamic]";
                                    }
                                    else if (pf.InitialSize == pf.MaximumSize)
                                    {
                                        pf.Comment = "Custom Managed [Fixed]";
                                    }
                                    else
                                    {
                                        pf.Comment = "Custom Managed [Dynamic]";
                                    }

                                    break;
                                }
                            }

                            innerSearcher.Dispose();
                            break;
                        }
                    }
                }

                // ******************************
                // Query PageFile Automatic Management Setting.
                // ******************************

                ObjectQuery autoQuery = new("SELECT AutomaticManagedPagefile FROM Win32_ComputerSystem");
                searcher = new ManagementObjectSearcher(scope, autoQuery);

                foreach (ManagementObject m in searcher.Get())
                {
                    if (m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("TRUE"))
                    {
                        foreach (PageFile p in PageFiles)
                        {
                            p.Comment = "Automatic Management";
                            p.AutomaticManagement = true;
                        }
                    }
                }

                searcher.Dispose();
                return true;
            }
            catch (Exception e)
            {
                _logFile.Log(e, "Failed to read page file configuration");
                return false;
            }
        }

        public void DisplayConfig()
        {
            foreach (PageFile p in PageFiles)
            {
                _logFile.Log($"Drive: {p.DriveLetter}");
                _logFile.Log($"  Comment: {p.Comment}");
                _logFile.Log($"  Initial Size: {p.InitialSize}MB");
                _logFile.Log($"  Maximum Size: {p.MaximumSize}MB");
                _logFile.Log($"  Allocated Size: {p.AllocatedBaseSize}MB");
                _logFile.Log($"  Current usage: {p.CurrentUsage}MB");
                _logFile.Log($"  Peak usage: {p.PeakUsage}MB");
            }
        }

        public bool ConfigureAutomaticPageFile(bool enable)
        {
            try
            {
                IntPtr hProcess = Process.GetCurrentProcess().Handle;

                if (NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_ALL_ACCESS, out IntPtr hToken) == false)
                {
                    _logFile.Log("ERROR: Unable to open specified process token [OpenProcessToken=" + Marshal.GetLastWin32Error().ToString() + "]", SimpleLogger.MsgType.ERROR);
                }

                new WindowsHelper(_logFile).EnablePrivilege(hToken, NativeMethods.SE_CREATE_PAGEFILE_NAME);
                _logFile.Log($"Configure automatic page file management [Enable={enable.ToString().ToUpper()}]...");

                ManagementScope scope = new(@"\\.\root\cimv2");
                scope.Connect();
                ObjectQuery query = new($"SELECT * FROM Win32_ComputerSystem");
                ManagementObjectSearcher searcher = new(scope, query);

                foreach (ManagementObject m in searcher.Get())
                {
                    if (enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("FALSE"))
                    {
                        _logFile.Log("Current setting: OFF");
                        _logFile.Log("New setting: ON");
                        m["AutomaticManagedPagefile"] = true;
                        m.Put();
                        _logFile.Log("Configuration successful");
                    }
                    else if (enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("TRUE"))
                    {
                        _logFile.Log("Current setting: ON");
                        _logFile.Log("No configuration changes required");
                    }
                    else if (!enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("FALSE"))
                    {
                        _logFile.Log("Current setting: OFF");
                        _logFile.Log("No configuration changes required");
                    }
                    else if (!enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("TRUE"))
                    {
                        _logFile.Log("Current setting: ON");
                        _logFile.Log("New setting: OFF");
                        m["AutomaticManagedPagefile"] = false;
                        m.Put();
                        _logFile.Log("Configuration successful");
                    }
                }

                return true;
            }
            catch (Exception e)
            {
                _logFile.Log(e, "Failed to update automatic page file configuration");
                return false;
            }
        }

        public bool ConfigureManualPageFile(string driveLetter, int initSize, int maxSize)
        {
            try
            {
                // ******************************
                // Turn OFF Automatic Page File Management.
                // ******************************

                _logFile.Log("Ensure automatic page file management is OFF...");
                bool success = ConfigureAutomaticPageFile(false);

                if (!success)
                {
                    _logFile.Log("ERROR: Failed to TURN OFF automatic page file management, further actions cancelled", SimpleLogger.MsgType.ERROR);
                    return false;
                }

                _logFile.Log("Perform manual configuration...");
                _logFile.Log($"  Drive letter: {driveLetter}:\\");
                _logFile.Log($"  Initial Size: {initSize}");
                _logFile.Log($"  Maximum Size: {maxSize}");

                // ******************************
                // Verify Free Disk Space Available.
                // ******************************

                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    if (d.Name.ToUpper().Substring(0, 1).Equals(driveLetter.ToUpper()))
                    {
                        long freeSpaceMB = d.TotalFreeSpace / 1048576; // 1 MB = 1,048,576 bytes

                        if (maxSize > freeSpaceMB)
                        {
                            _logFile.Log($"ERROR: Page file maximum size [{maxSize}MB] exceeds available free disk space [{freeSpaceMB}MB]", SimpleLogger.MsgType.ERROR);
                            return false;
                        }
                        else
                        {
                            break;
                        }
                    }
                }

                // ******************************
                // Update Page File Settings.
                // ******************************

                ManagementScope scope = new(@"\\.\root\cimv2");
                scope.Connect();
                ObjectQuery query = new("SELECT * FROM Win32_PageFileSetting");
                ManagementObjectSearcher searcher = new(scope, query);
                ManagementObjectCollection queryCollection = searcher.Get();
                bool matchFound = false;

                foreach (ManagementObject m in queryCollection)
                {
                    if (m["Name"].ToString().ToUpper().StartsWith(driveLetter.ToUpper()))
                    {
                        _logFile.Log("Update existing page file configuration...");
                        matchFound = true;
                        m["InitialSize"] = initSize;
                        m["MaximumSize"] = maxSize;
                        m.Put();
                        break;
                    }
                }

                if (queryCollection.Count == 0 || !matchFound)
                {
                    _logFile.Log("Create new page file configuration...");
                    ManagementClass mc = new(@"\\.\root\cimv2", "Win32_PageFileSetting", null);
                    ManagementObject mo = mc.CreateInstance();
                    mo["Caption"] = $"{driveLetter.ToUpper()}:\\ 'pagefile.sys'";
                    mo["Description"] = $"'pagefile.sys' @ {driveLetter.ToUpper()}:\\";
                    mo["InitialSize"] = initSize;
                    mo["MaximumSize"] = maxSize;
                    mo["Name"] = $"{driveLetter.ToUpper()}:\\pagefile.sys";
                    mo["SettingID"] = $"pagefile.sys @ {driveLetter.ToUpper()}:";
                    PutOptions options = new();
                    options.Type = PutType.CreateOnly;
                    mo.Put(options);
                    mo.Dispose();
                    mc.Dispose();
                }

                searcher.Dispose();
                _logFile.Log("Configuration successful");
                return true;
            }
            catch (Exception e)
            {
                _logFile.Log(e, "Failed to update page file configuration");
                return false;
            }
        }

        public bool RemovePageFile(string driveLetter)
        {
            try
            {
                // ******************************
                // Turn OFF Automatic Page File Management.
                // ******************************

                _logFile.Log("Ensure automatic page file management is OFF...");
                bool success = ConfigureAutomaticPageFile(false);

                if (success == false)
                {
                    _logFile.Log("ERROR: Failed to TURN OFF automatic page file management, further actions cancelled", SimpleLogger.MsgType.ERROR);
                    return false;
                }

                // ******************************
                // Remove Page File Configuration.
                // ******************************

                _logFile.Log("Remove page file configuration...");
                _logFile.Log($"  Drive letter: {driveLetter}");
                ManagementScope scope = new(@"\\.\root\cimv2");
                scope.Connect();
                ObjectQuery query = new("SELECT * FROM Win32_PageFileSetting");
                ManagementObjectSearcher searcher = new(scope, query);
                ManagementObjectCollection queryCollection = searcher.Get();
                bool matchFound = false;

                foreach (ManagementObject m in queryCollection)
                {
                    if (m["Name"].ToString().ToUpper().StartsWith(driveLetter.ToUpper()))
                    {
                        _logFile.Log("Found page file configuration, removing...");
                        matchFound = true;
                        m.Delete();
                        break;
                    }
                }

                if (queryCollection.Count == 0 || !matchFound)
                {
                    _logFile.Log($"ERROR: Removal failed, no page file is currently configured for {driveLetter}:\\", SimpleLogger.MsgType.ERROR);
                    return false;
                }

                searcher.Dispose();
                _logFile.Log("Removal successful");
                return true;
            }
            catch (Exception e)
            {
                _logFile.Log(e, "Failed to update page file configuration");
                return false;
            }
        }
    }
}
