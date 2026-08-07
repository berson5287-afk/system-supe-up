"""What the common Windows processes actually are, and what to do about them.

A monitor that says "svchost.exe is using 40% CPU" has told the user nothing,
because there are thirty svchost processes and the name is a container, not an
identity.  This table is the difference between naming a process and explaining
it — and, more importantly, it is what stops the tool giving dangerous advice.
"End task on lsass.exe" would bluescreen the machine, and a model asked to
suggest fixes will happily say it.

`killable` is therefore load-bearing rather than decorative: nothing in the
rest of the program may offer to stop a process this table has not cleared.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Fix:
    """One remedy, written so a person can decide whether they want it."""

    title: str
    detail: str
    #: A command the user could run.  Never executed without confirmation, and
    #: never populated for anything that cannot be undone.
    command: str = ""
    #: low = reversible and obvious, medium = changes behaviour, high = needs
    #: thought (disabling security software, editing the registry).
    risk: str = "low"
    needs_admin: bool = False


@dataclass
class ProcessFact:
    display: str
    role: str
    category: str = "app"
    vendor: str = ""
    #: A documented, reproducible leak — this program grows without bound
    #: regardless of what the user does. Worth calling out by name, because
    #: the symptom (a machine fine in the morning and unusable by evening)
    #: looks nothing like its cause and nobody ever suspects the vendor's own
    #: support agent.
    known_leak: bool = False
    #: Windows falls over without it.  Overrides everything else.
    essential: bool = False
    #: Safe to end from Task Manager: the app may lose unsaved work, but the
    #: system stays up and the process comes back or is not needed.
    killable: bool = True
    common_causes: list[str] = field(default_factory=list)
    fixes: list[Fix] = field(default_factory=list)


def _f(title: str, detail: str, command: str = "", risk: str = "low",
       admin: bool = False) -> Fix:
    return Fix(title=title, detail=detail, command=command, risk=risk,
               needs_admin=admin)


# Real-time scanners.  Two of these running at once is one of the largest
# unforced slowdowns a Windows machine can have — every file operation is
# inspected twice, and each scanner's own reads are inspected by the other.
REALTIME_AV = {
    "msmpeng.exe": "Microsoft Defender",
    "sentinelagent.exe": "SentinelOne",
    "sentinelservicehost.exe": "SentinelOne",
    "sentinelstaticengine.exe": "SentinelOne",
    "avgsvc.exe": "AVG",
    "avgui.exe": "AVG",
    "aswidsagent.exe": "Avast/AVG",
    "avastsvc.exe": "Avast",
    "mcshield.exe": "McAfee",
    "masvc.exe": "McAfee",
    "ekrn.exe": "ESET",
    "nortonsecurity.exe": "Norton",
    "ns.exe": "Norton",
    "csfalconservice.exe": "CrowdStrike Falcon",
    "sophosfilescanner.exe": "Sophos",
    "savservice.exe": "Sophos",
    "bdagent.exe": "Bitdefender",
    "vsserv.exe": "Bitdefender",
    "ccsvchst.exe": "Symantec",
    "tmbmsrv.exe": "Trend Micro",
    "coreserviceshell.exe": "Trend Micro",
    "wrsa.exe": "Webroot",
    "mbamservice.exe": "Malwarebytes",
    "cylancesvc.exe": "Cylance",
    "cybereasonranger.exe": "Cybereason",
    "elastic-endpoint.exe": "Elastic Defend",
}


KNOWN: dict[str, ProcessFact] = {

    # ---------------------------------------------------------- core Windows
    "system": ProcessFact(
        "System (kernel)",
        "The Windows kernel itself, plus every driver's worker threads.",
        "system", "Microsoft", essential=True, killable=False,
        common_causes=[
            "A slow or faulty driver — storage, network or a security filter "
            "driver — blocking inside a kernel call",
            "Heavy disk or network work done on behalf of other processes",
            "Failing storage retrying reads"],
        fixes=[
            _f("Find the driver behind it",
               "System's CPU belongs to whichever driver is busy. Run the "
               "Windows Performance Recorder or `driverquery /v` and compare "
               "against recently updated drivers.",
               "driverquery /v /fo table"),
            _f("Check the disk for errors",
               "A drive retrying failed reads shows up as System time and "
               "long kernel waits.",
               "chkdsk C: /scan", risk="low", admin=True)]),

    "registry": ProcessFact(
        "Registry", "Where Windows keeps the registry hives in memory.",
        "system", "Microsoft", essential=True, killable=False,
        common_causes=["Registry hive paging under memory pressure"]),

    "memory compression": ProcessFact(
        "Memory Compression",
        "Compresses pages that would otherwise be written to the page file.",
        "system", "Microsoft", essential=True, killable=False,
        common_causes=[
            "Not enough RAM — this process grows precisely because the "
            "machine is short of memory, so it is a symptom rather than a "
            "cause"],
        fixes=[
            _f("Treat it as a RAM shortage, not a rogue process",
               "Memory Compression using a lot of CPU or memory means Windows "
               "is compressing pages instead of keeping them whole. Close "
               "large applications or add RAM; there is nothing to fix in "
               "this process itself.")]),

    "memcompression": ProcessFact(
        "Memory Compression",
        "Compresses pages that would otherwise be written to the page file.",
        "system", "Microsoft", essential=True, killable=False),

    "svchost.exe": ProcessFact(
        "Service Host",
        "A container that runs Windows services — the name says nothing "
        "about what it is doing; the services inside it do.",
        "system", "Microsoft", essential=True, killable=False,
        common_causes=[
            "Windows Update scanning or downloading (wuauserv)",
            "The Delivery Optimization peer-to-peer uploader (DoSvc)",
            "Superfetch/SysMain prefetching on a machine short of RAM",
            "The Connected User Experiences telemetry service (DiagTrack)",
            "The Windows Search indexer's service half"],
        fixes=[
            _f("Identify which service is actually busy",
               "Every svchost hosts named services. List them for the pid "
               "before doing anything else — the fix depends entirely on "
               "which one it is.",
               "tasklist /svc /fi \"PID eq {pid}\""),
            _f("Turn off SysMain if this machine has an SSD",
               "SysMain (Superfetch) pre-loads applications into RAM. On an "
               "SSD it buys almost nothing and on a machine short of memory "
               "it actively hurts.",
               "sc config SysMain start=disabled & sc stop SysMain",
               risk="medium", admin=True),
            _f("Cap Delivery Optimization",
               "DoSvc uploads Windows updates to other machines and can "
               "saturate an upstream link. Settings > Windows Update > "
               "Advanced > Delivery Optimization.", risk="low")]),

    "lsass.exe": ProcessFact(
        "Local Security Authority",
        "Handles sign-in, passwords and security tokens.",
        "system", "Microsoft", essential=True, killable=False,
        common_causes=["Domain authentication storms", "Credential Guard work"],
        fixes=[_f("Never end this process",
                  "Ending lsass.exe forces an immediate reboot with data "
                  "loss. If it is genuinely busy, the cause is on the domain "
                  "controller or in an authentication loop, not here.")]),

    "csrss.exe": ProcessFact(
        "Client/Server Runtime",
        "Handles console windows and part of the windowing system.",
        "system", "Microsoft", essential=True, killable=False,
        common_causes=[
            "Blocked waiting on an application that has stopped responding — "
            "csrss is usually a victim, not a cause"]),

    "dwm.exe": ProcessFact(
        "Desktop Window Manager",
        "Composites everything you see on screen.",
        "system", "Microsoft", essential=True, killable=False,
        common_causes=[
            "A graphics driver problem",
            "An application flooding it with redraws",
            "Blocked drawing a window whose owner has hung — the visible "
            "symptom is the whole desktop stuttering, but the fault is the "
            "hung application"],
        fixes=[
            _f("Update or roll back the graphics driver",
               "DWM sits directly on the display driver, so its stalls are "
               "usually the driver's."),
            _f("Reduce visual effects",
               "Transparency and animations are the most expensive things "
               "DWM does.",
               "SystemPropertiesPerformance.exe")]),

    "explorer.exe": ProcessFact(
        "Windows Explorer",
        "The desktop, taskbar, Start menu and every file window.",
        "system", "Microsoft", essential=False, killable=True,
        common_causes=[
            "A third-party shell extension misbehaving — added by archivers, "
            "cloud sync clients and antivirus, and the single most common "
            "cause of Explorer hanging on right-click",
            "A folder full of media files whose thumbnails cannot be built",
            "A disconnected network drive it keeps retrying",
            "Cloud sync placeholders waiting on the network"],
        fixes=[
            _f("Restart Explorer",
               "Costs nothing but your open folder windows, and clears a "
               "leaked handle or thread count immediately.",
               "taskkill /f /im explorer.exe & start explorer.exe"),
            _f("Audit shell extensions",
               "Disable non-Microsoft shell extensions in bulk, then "
               "re-enable them a few at a time. NirSoft ShellExView is the "
               "usual tool.", risk="medium"),
            _f("Clear the thumbnail cache",
               "A corrupt thumbnail database makes Explorer hang on any "
               "folder containing the offending file.",
               "cleanmgr /sagerun:1")]),

    "searchindexer.exe": ProcessFact(
        "Windows Search Indexer",
        "Builds the index behind Start menu and File Explorer search.",
        "system", "Microsoft", essential=False, killable=True,
        common_causes=[
            "A first-time or rebuilt index crawling the whole disk",
            "Indexing a large mailbox or a cloud-synced folder",
            "A corrupt index restarting the crawl endlessly"],
        fixes=[
            _f("Narrow what is indexed",
               "Remove large media, archive and code folders from the "
               "indexed locations — they are rarely searched by content.",
               "control srchadmin.dll"),
            _f("Rebuild a corrupt index",
               "An index that never finishes is usually damaged; rebuilding "
               "costs one slow evening and then stops.",
               "control srchadmin.dll", risk="medium")]),

    "tiworker.exe": ProcessFact(
        "Windows Modules Installer Worker",
        "Installs and verifies Windows updates in the background.",
        "system", "Microsoft", essential=False, killable=False,
        common_causes=["An update installing", "A component store health scan"],
        fixes=[_f("Let it finish",
                  "TiWorker is genuinely doing work and killing it can leave "
                  "the component store inconsistent. If it runs for days, "
                  "repair the store.",
                  "DISM /Online /Cleanup-Image /RestoreHealth",
                  risk="medium", admin=True)]),

    "trustedinstaller.exe": ProcessFact(
        "Windows Modules Installer",
        "The service that owns Windows component installation.",
        "system", "Microsoft", essential=False, killable=False),

    "wmiprvse.exe": ProcessFact(
        "WMI Provider Host",
        "Answers management queries about the machine.",
        "system", "Microsoft", essential=False, killable=True,
        common_causes=[
            "A monitoring agent, inventory tool or script polling WMI in a "
            "loop — the culprit is whatever is asking, not this process"],
        fixes=[
            _f("Find who is querying it",
               "WMI-Activity operational log records the client process for "
               "every query.",
               "wevtutil qe Microsoft-Windows-WMI-Activity/Operational /c:20 /f:text")]),

    "runtimebroker.exe": ProcessFact(
        "Runtime Broker",
        "Polices permissions for Store apps.",
        "system", "Microsoft", essential=False, killable=True,
        common_causes=["A misbehaving Store app", "Photos app background work"]),

    "audiodg.exe": ProcessFact(
        "Audio Device Graph",
        "Runs audio effects processing out of process.",
        "system", "Microsoft", essential=False, killable=True,
        common_causes=["Third-party audio 'enhancements' from the sound driver"],
        fixes=[_f("Disable audio enhancements",
                  "Vendor effects run here and are a common cause of audio "
                  "stutter and steady CPU use.", "mmsys.cpl")]),

    "spoolsv.exe": ProcessFact(
        "Print Spooler", "Queues print jobs.", "system", "Microsoft",
        essential=False, killable=True,
        common_causes=["A stuck print job", "A broken printer driver"],
        fixes=[_f("Clear the print queue",
                  "A jammed job keeps the spooler spinning forever.",
                  "net stop spooler & del /q /f %systemroot%\\System32\\spool"
                  "\\PRINTERS\\* & net start spooler",
                  risk="medium", admin=True)]),

    "ctfmon.exe": ProcessFact(
        "Text Input Host", "Handles keyboard layouts, handwriting and IME.",
        "system", "Microsoft", essential=False, killable=True),
    "fontdrvhost.exe": ProcessFact(
        "Font Driver Host", "Renders fonts out of process.",
        "system", "Microsoft", essential=True, killable=False),
    "sihost.exe": ProcessFact(
        "Shell Infrastructure Host", "Runs parts of the shell UI.",
        "system", "Microsoft", essential=False, killable=True),
    "smss.exe": ProcessFact(
        "Session Manager", "Starts Windows sessions.", "system", "Microsoft",
        essential=True, killable=False),
    "wininit.exe": ProcessFact(
        "Windows Start-Up", "Starts the system session.", "system",
        "Microsoft", essential=True, killable=False),
    "services.exe": ProcessFact(
        "Service Control Manager", "Starts and stops Windows services.",
        "system", "Microsoft", essential=True, killable=False),
    "secure system": ProcessFact(
        "Secure System", "Virtualisation-based security.", "system",
        "Microsoft", essential=True, killable=False),

    # ------------------------------------------------------------- browsers
    "chrome.exe": ProcessFact(
        "Google Chrome", "Web browser; one process per tab and extension.",
        "browser", "Google", killable=True,
        common_causes=[
            "A single tab running away — a script loop, a stuck video player "
            "or a page that never finishes loading",
            "Too many tabs for the available RAM, which turns into paging",
            "An extension leaking memory or blocking the browser's UI thread",
            "Hardware acceleration fighting a graphics driver"],
        fixes=[
            _f("Use Chrome's own task manager to find the tab",
               "Shift+Esc lists every tab and extension by CPU and memory. "
               "The parent chrome.exe is rarely the problem; one child is."),
            _f("Turn on Memory Saver",
               "Discards tabs you have not touched, which is the direct cure "
               "for tab-count paging. Settings > Performance."),
            _f("Test with extensions disabled",
               "Open an incognito window — extensions are off by default "
               "there. If the problem vanishes, bisect the extensions.",
               risk="low"),
            _f("Turn off hardware acceleration",
               "If the hangs come with graphical glitches, this is usually "
               "the driver. Settings > System > Use hardware acceleration.",
               risk="low")]),

    "msedge.exe": ProcessFact(
        "Microsoft Edge", "Web browser; one process per tab and extension.",
        "browser", "Microsoft", killable=True,
        common_causes=["A runaway tab or extension", "Too many tabs for the RAM",
                       "Startup boost keeping it resident when closed"],
        fixes=[
            _f("Use Edge's task manager", "Shift+Esc to find the tab."),
            _f("Turn off startup boost and background running",
               "Edge otherwise keeps processes alive after you close it. "
               "Settings > System and performance.")]),

    "msedgewebview2.exe": ProcessFact(
        "Edge WebView2",
        "An embedded browser other applications use for their interface — "
        "Teams, Outlook's new UI, Office panes and many installers.",
        "browser", "Microsoft", killable=True,
        common_causes=[
            "The host application, not the WebView itself — find the parent",
            "Several applications each running their own WebView copy"],
        fixes=[_f("Identify the host application",
                  "WebView2 is a passenger. Its parent process is the "
                  "application to actually investigate.",
                  "wmic process where ProcessId={pid} get ParentProcessId")]),

    "firefox.exe": ProcessFact(
        "Mozilla Firefox", "Web browser.", "browser", "Mozilla", killable=True,
        common_causes=["A runaway tab or extension", "A corrupt profile"],
        fixes=[_f("Use about:processes", "Firefox's own per-tab breakdown."),
               _f("Refresh the profile",
                  "about:support > Refresh Firefox keeps bookmarks and "
                  "passwords but resets extensions and settings.",
                  risk="medium")]),

    # ---------------------------------------------------------- Office/comms
    "outlook.exe": ProcessFact(
        "Microsoft Outlook", "Mail and calendar client.", "office",
        "Microsoft", killable=True,
        common_causes=[
            "A very large or damaged OST/PST data file",
            "Add-ins — the most common cause of Outlook freezing on start or "
            "when opening a message",
            "Rebuilding the search index over a big mailbox",
            "An archive or cloud-synced data file on a slow path"],
        fixes=[
            _f("Start Outlook without add-ins to confirm",
               "If safe mode is smooth, an add-in is the cause; re-enable "
               "them a few at a time.", "outlook.exe /safe"),
            _f("Check the data file size",
               "OST files over about 25 GB slow down noticeably and over "
               "50 GB behave badly. Reduce the sync window to 3-6 months in "
               "Account Settings.", risk="low"),
            _f("Repair the data file",
               "SCANPST.EXE, in the Office install folder, fixes the "
               "corruption that causes random freezes.", risk="medium")]),

    "excel.exe": ProcessFact(
        "Microsoft Excel", "Spreadsheet application.", "office", "Microsoft",
        killable=True,
        common_causes=[
            "A workbook with heavy volatile formulas recalculating",
            "Links to other workbooks on a slow network path",
            "Add-ins", "Conditional formatting applied to whole columns"],
        fixes=[
            _f("Switch to manual calculation while editing",
               "Formulas > Calculation Options > Manual stops a full "
               "recalculation after every keystroke."),
            _f("Start without add-ins to confirm", "", "excel.exe /safe")]),

    "winword.exe": ProcessFact(
        "Microsoft Word", "Word processor.", "office", "Microsoft",
        killable=True,
        common_causes=["Add-ins", "A document with tracked changes over years",
                       "A slow or unreachable default printer"],
        fixes=[_f("Start without add-ins", "", "winword.exe /safe")]),

    "teams.exe": ProcessFact(
        "Microsoft Teams", "Chat and meetings client.", "comms", "Microsoft",
        killable=True,
        common_causes=["A large cache", "Background video processing",
                       "GPU acceleration on a weak graphics chip"],
        fixes=[_f("Clear the Teams cache",
                  "Quit Teams first; it is rebuilt on next start.",
                  "rmdir /s /q %appdata%\\Microsoft\\Teams\\Cache",
                  risk="medium")]),

    "ms-teams.exe": ProcessFact(
        "Microsoft Teams (new)", "Chat and meetings client.", "comms",
        "Microsoft", killable=True),

    "slack.exe": ProcessFact(
        "Slack", "Chat client built on Electron.", "comms", "Slack",
        killable=True,
        common_causes=["Many workspaces open at once", "A large local cache"]),

    "zoom.exe": ProcessFact(
        "Zoom", "Video conferencing.", "comms", "Zoom", killable=True,
        common_causes=["Virtual background processing without GPU support"]),

    "discord.exe": ProcessFact(
        "Discord", "Chat client built on Electron.", "comms", "Discord",
        killable=True,
        common_causes=["Hardware acceleration issues", "Overlay hooking games"]),

    # -------------------------------------------------------------- sync
    "onedrive.exe": ProcessFact(
        "Microsoft OneDrive", "Syncs files to OneDrive/SharePoint.",
        "sync", "Microsoft", killable=True,
        common_causes=[
            "A large initial sync or a bulk change re-uploading everything",
            "Files On-Demand fetching placeholders as applications open them, "
            "which turns a local file read into a network round trip",
            "A sync conflict loop on a file two machines keep changing",
            "Syncing a folder full of small files — the per-file overhead "
            "dominates and pins the disk"],
        fixes=[
            _f("Pause syncing to confirm it is the cause",
               "Pause for an hour from the taskbar icon. If the machine "
               "recovers, it is the sync, not the application you blamed."),
            _f("Stop syncing folders that do not need it",
               "Development folders, virtual machine images and archives sync "
               "endlessly and are rarely wanted in the cloud."),
            _f("Free up space rather than keeping everything local",
               "Right-click the folder > Free up space, so files download "
               "only on use.", risk="low")]),

    "dropbox.exe": ProcessFact(
        "Dropbox", "File sync client.", "sync", "Dropbox", killable=True,
        common_causes=["Bulk re-index after a large change",
                       "Smart Sync placeholder fetches"]),

    "googledrivefs.exe": ProcessFact(
        "Google Drive", "File sync client.", "sync", "Google", killable=True,
        common_causes=["Streaming mode fetching files on access"]),

    # ---------------------------------------------------------- security
    "msmpeng.exe": ProcessFact(
        "Microsoft Defender Antivirus", "Real-time malware scanning.",
        "security", "Microsoft", essential=False, killable=False,
        common_causes=[
            "A scheduled full scan running during working hours",
            "Scanning a compiler, package manager or VM disk that writes "
            "thousands of files a minute",
            "Fighting a second real-time antivirus product"],
        fixes=[
            _f("Move the scheduled scan out of working hours",
               "Task Scheduler > Microsoft > Windows > Windows Defender."),
            _f("Exclude high-churn build and VM folders",
               "Scanning every intermediate build artefact is pure waste. "
               "Exclude source trees, package caches and .vhdx files.",
               risk="medium", admin=True),
            _f("Make sure only one real-time scanner is active",
               "Defender is supposed to stand down when a third-party product "
               "registers, but often does not fully.", risk="medium")]),

    "sentinelagent.exe": ProcessFact(
        "SentinelOne Agent", "Endpoint detection and response agent.",
        "security", "SentinelOne", essential=False, killable=False,
        common_causes=[
            "Deep inspection of file and process activity",
            "A full disk scan pushed by the management console",
            "Overlapping with another real-time scanner"],
        fixes=[
            _f("Raise it with whoever manages the console",
               "SentinelOne is centrally managed and tamper-protected — "
               "exclusions and scan windows have to be changed server-side, "
               "not on this machine.", risk="high")]),

    "sentinelservicehost.exe": ProcessFact(
        "SentinelOne Service Host", "Endpoint agent service host.",
        "security", "SentinelOne", essential=False, killable=False),
    "sentinelstaticengine.exe": ProcessFact(
        "SentinelOne Static Engine", "On-access file inspection.",
        "security", "SentinelOne", essential=False, killable=False),

    "avgsvc.exe": ProcessFact(
        "AVG Antivirus Service", "Third-party real-time antivirus.",
        "security", "AVG", essential=False, killable=False,
        common_causes=["Scheduled scans", "Overlapping with another scanner"],
        fixes=[
            _f("Do not run two real-time scanners",
               "If a managed EDR product is already installed, a consumer "
               "antivirus alongside it adds no protection and doubles the "
               "cost of every file operation.", risk="high")]),

    "csfalconservice.exe": ProcessFact(
        "CrowdStrike Falcon Sensor", "Endpoint detection and response.",
        "security", "CrowdStrike", essential=False, killable=False,
        fixes=[_f("Managed centrally",
                  "Exclusions are set in the Falcon console, not locally.",
                  risk="high")]),

    # --------------------------------------------------------------- OEM
    "dell.techhub.instrumentation.subagent.exe": ProcessFact(
        "Dell TechHub Instrumentation", "Dell telemetry and diagnostics agent.",
        "oem", "Dell", killable=True,
        common_causes=["Continuous hardware polling and telemetry upload"],
        fixes=[_f("Reduce or remove Dell Optimizer / SupportAssist",
                  "These agents poll hardware constantly and are optional. "
                  "Uninstall from Apps & features if unused.",
                  risk="medium")]),
    "dell.techhub.diagnostics.subagent.exe": ProcessFact(
        "Dell TechHub Diagnostics", "Dell diagnostics agent.", "oem", "Dell",
        killable=True),
    "dell.techhub.exe": ProcessFact(
        "Dell TechHub", "Dell agent host.", "oem", "Dell", killable=True),
    "serviceshell.exe": ProcessFact(
        "Dell SupportAssist (ServiceShell)",
        "The host process behind Dell SupportAssist / Dell Optimizer.",
        "oem", "Dell", known_leak=True, essential=False, killable=True,
        common_causes=[
            "A well-documented memory leak — Dell's own support forums carry "
            "reports of this process climbing into tens of gigabytes over "
            "days of uptime, growing steadily rather than in response to any "
            "workload",
            "Continuous hardware telemetry and scheduled scans"],
        fixes=[
            _f("Close it now to get the memory back",
               "It restarts on its own or at next sign-in. On a machine short "
               "of RAM this is worth doing whenever the count has crept up.",
               "taskkill /f /im ServiceShell.exe", risk="medium"),
            _f("Uninstall SupportAssist if you do not use it",
               "This is the real fix. SupportAssist is a convenience tool for "
               "driver updates and diagnostics — nothing depends on it, and "
               "removing it removes the leak permanently. Apps & features > "
               "Dell SupportAssist.", risk="medium"),
            _f("Check for a SupportAssist update first",
               "Dell has fixed versions of this leak more than once, so an "
               "update may settle it if you want to keep the tool.",
               risk="low")]),

    # Dell's own spelling of "Remediation" — matched exactly as shipped,
    # because a lookup table that silently misses is worse than one that is
    # obviously incomplete.
    "dellsupportassistremedationservice.exe": ProcessFact(
        "Dell SupportAssist Remediation",
        "The service half of Dell SupportAssist, which applies fixes and "
        "driver updates.", "oem", "Dell", essential=False, killable=True,
        common_causes=["Scheduled remediation and driver scans"],
        fixes=[_f("Remove SupportAssist entirely if unused",
                  "This service, ServiceShell.exe and SupportAssistAgent.exe "
                  "are all parts of the same optional product. Removing it "
                  "takes all three away at once.", risk="medium")]),
    "avgtoolssvc.exe": ProcessFact(
        "AVG Tools Service", "Supporting service for AVG Antivirus.",
        "security", "AVG", essential=False, killable=False),
    "avgnt.exe": ProcessFact(
        "Avira/AVG notifier", "Antivirus tray notifier.", "security", "AVG",
        killable=True),

    "supportassistagent.exe": ProcessFact(
        "Dell SupportAssist", "Dell support and update agent.", "oem", "Dell",
        killable=True,
        fixes=[_f("Uninstall if unused",
                  "SupportAssist scans and phones home on a schedule.",
                  risk="medium")]),
    "armourycrate.exe": ProcessFact(
        "ASUS Armoury Crate", "ASUS lighting and fan control.", "oem", "ASUS",
        killable=True,
        fixes=[_f("Uninstall if you do not use the lighting features",
                  "Widely reported as a heavy background load.",
                  risk="medium")]),
    "icue.exe": ProcessFact(
        "Corsair iCUE", "Corsair peripheral and lighting control.", "oem",
        "Corsair", killable=True),
    "razer synapse.exe": ProcessFact(
        "Razer Synapse", "Razer peripheral configuration.", "oem", "Razer",
        killable=True),
    "lenovovantageservice.exe": ProcessFact(
        "Lenovo Vantage", "Lenovo system management.", "oem", "Lenovo",
        killable=True),

    # -------------------------------------------------- managed endpoint kit
    # Deliberately NOT in REALTIME_AV. Huntress leans on Defender for file
    # scanning and adds detection telemetry on top, so counting it as a second
    # real-time scanner would overstate the "two scanners fighting" finding —
    # which is a serious enough accusation that it must only fire when it is
    # actually true.
    "huntressagent.exe": ProcessFact(
        "Huntress Agent",
        "Managed detection and response agent, deployed and watched by an IT "
        "provider.", "security", "Huntress", essential=False, killable=False,
        common_causes=["Scheduled survey of installed software and persistence "
                       "points", "An investigation pushed from the console"],
        fixes=[_f("Managed centrally",
                  "This is your IT provider's tooling — changes go through "
                  "them, and it is tamper-protected locally.", risk="high")]),
    "huntressrio.exe": ProcessFact(
        "Huntress Rio", "Huntress detection engine.", "security", "Huntress",
        essential=False, killable=False),
    # The Rio component ships under a bare name, which makes it look like an
    # unidentified stranger holding a couple of hundred megabytes.
    "rio.exe": ProcessFact(
        "Huntress Rio",
        "Huntress' detection engine, deployed alongside the Huntress agent.",
        "security", "Huntress", essential=False, killable=False,
        fixes=[_f("Managed centrally",
                  "Part of your IT provider's tooling; changes go through "
                  "them.", risk="high")]),
    "huntressupdater.exe": ProcessFact(
        "Huntress Updater", "Keeps the Huntress agent current.", "security",
        "Huntress", killable=False),

    "ninjarmmagent.exe": ProcessFact(
        "NinjaOne RMM Agent",
        "Remote monitoring and management agent — inventory, patching and "
        "remote access for an IT provider.", "remote", "NinjaOne",
        essential=False, killable=False,
        common_causes=["Scheduled inventory and patch scans",
                       "Software deployment pushed from the console",
                       "Performance monitoring polling on a short interval"],
        fixes=[_f("Check the scan schedule with whoever manages it",
                  "RMM agents are usually configured to scan far more often "
                  "than anyone needs, and the schedule is set server-side.",
                  risk="medium")]),
    "ninjarmmagentpatcher.exe": ProcessFact(
        "NinjaOne Patcher", "Applies patches on behalf of the RMM agent.",
        "remote", "NinjaOne", killable=False),

    "ccleaner_service.exe": ProcessFact(
        "CCleaner Service",
        "Background service for CCleaner, a disk and registry cleaning tool.",
        "util", "Gen Digital", essential=False, killable=True,
        common_causes=["Scheduled 'health check' scans",
                       "Active monitoring watching the file system"],
        fixes=[
            _f("Turn off active monitoring",
               "CCleaner's background monitoring watches file activity "
               "continuously to report how much it could clean. Turning it "
               "off leaves the tool available on demand and removes the "
               "constant cost. Options > Smart Cleaning.", risk="low"),
            _f("Be sceptical of registry cleaning",
               "Registry cleaning has no measurable performance benefit on "
               "modern Windows and carries a real risk of removing something "
               "needed. Disk cleanup is the part worth keeping.",
               risk="medium")]),

    "delloptimizer.exe": ProcessFact(
        "Dell Optimizer",
        "Dell's tuning agent — application learning, audio and power "
        "profiles.", "oem", "Dell", killable=True,
        common_causes=["Continuous application-usage profiling",
                       "Background hardware polling"],
        fixes=[_f("Uninstall if you do not use its features",
                  "Dell Optimizer profiles what you run in order to pre-load "
                  "it, which costs more than it saves on a machine that is "
                  "already short of memory.", risk="medium")]),
    "delloptimizerui.exe": ProcessFact(
        "Dell Optimizer UI", "Dell Optimizer's interface.", "oem", "Dell",
        killable=True),

    "foxitpdfreaderupdateservice.exe": ProcessFact(
        "Foxit Reader Update Service", "Checks for Foxit PDF Reader updates.",
        "util", "Foxit", killable=True,
        fixes=[_f("Set it to check less often, or on demand",
                  "An updater does not need to be resident to work.",
                  risk="low")]),
    "openvpn-gui.exe": ProcessFact(
        "OpenVPN GUI", "Tray interface for OpenVPN.", "network", "OpenVPN",
        killable=True),

    # ------------------------------------------------------------ remote/net
    "screenconnect.clientservice.exe": ProcessFact(
        "ScreenConnect / ConnectWise Control",
        "Remote support agent that keeps a connection open to a support "
        "server.", "remote", "ConnectWise", killable=False,
        common_causes=["Reconnect loops when the server is unreachable",
                       "An active remote session capturing the screen"],
        fixes=[_f("Confirm it is expected",
                  "This is remote-access software. If your IT provider "
                  "installed it, it is normal; if not, treat it as urgent.",
                  risk="high")]),
    "tailscale-ipn.exe": ProcessFact(
        "Tailscale", "Mesh VPN client.", "network", "Tailscale", killable=True,
        common_causes=["Route or DNS churn", "Relay fallback when a direct "
                       "connection cannot be made"]),
    "tailscaled.exe": ProcessFact(
        "Tailscale Daemon", "Mesh VPN service.", "network", "Tailscale",
        killable=False),

    # ------------------------------------------------------------ dev/other
    "node.exe": ProcessFact(
        "Node.js", "A JavaScript program — the script decides the behaviour.",
        "dev", "", killable=True,
        common_causes=["A dev server watching too many files",
                       "A build or bundler running", "A runaway script"],
        fixes=[_f("Find out what it is running",
                  "The command line names the script.",
                  "wmic process where ProcessId={pid} get CommandLine")]),
    "python.exe": ProcessFact(
        "Python", "A Python program — the script decides the behaviour.",
        "dev", "", killable=True,
        fixes=[_f("Find out what it is running", "",
                  "wmic process where ProcessId={pid} get CommandLine")]),
    "pythonw.exe": ProcessFact(
        "Python (windowed)", "A Python GUI program.", "dev", "", killable=True),
    "java.exe": ProcessFact(
        "Java", "A Java application.", "dev", "", killable=True,
        common_causes=["A heap too small, causing constant garbage collection"]),
    # Local model servers. Worth naming precisely, because on a machine that
    # is short of RAM these are usually the largest single consumer and the
    # user is the one who started them — so "close the biggest application" is
    # advice they can act on immediately rather than a mystery.
    "ollama.exe": ProcessFact(
        "Ollama", "Local model server — the front end and model manager.",
        "ai", "Ollama", killable=True,
        common_causes=["A loaded model held in memory waiting for the next "
                       "request"],
        fixes=[_f("Unload the model instead of closing Ollama",
                  "Ollama keeps a model resident for five minutes after use "
                  "by default. Dropping it returns the memory immediately and "
                  "it reloads on next use.", risk="low"),
               _f("Shorten how long models stay resident",
                  "Set OLLAMA_KEEP_ALIVE to something like 60s, or 0 to "
                  "unload straight after each request.", risk="low")]),
    "ollama app.exe": ProcessFact(
        "Ollama (tray)", "Ollama's tray application.", "ai", "Ollama",
        killable=True),
    "ollama_llama_server.exe": ProcessFact(
        "Ollama model server",
        "The process actually holding a loaded model's weights in memory.",
        "ai", "Ollama", killable=True,
        common_causes=["A model loaded and resident — its memory is the "
                       "model's size, and it stays until unloaded"],
        fixes=[_f("Unload the model rather than killing this",
                  "Killing it works, but asking Ollama to unload is cleaner "
                  "and the next request still succeeds.", risk="low")]),
    "llama-server.exe": ProcessFact(
        "llama.cpp server",
        "A local model server holding an LLM's weights in memory — started "
        "directly, or by LM Studio or a script, rather than by Ollama.",
        "ai", "llama.cpp", killable=True,
        common_causes=[
            "A model loaded and resident. Its memory footprint is roughly the "
            "size of the model file and does not shrink while it runs",
            "Started by hand and left running after the work was finished"],
        fixes=[
            _f("Close it when not in use",
               "Unlike Ollama, a bare llama.cpp server does not unload on "
               "idle — it holds its full allocation until it exits.",
               risk="medium"),
            _f("Run the model on the other machine instead",
               "If a second box on the network has more memory, moving the "
               "model there removes the load from this one entirely.",
               risk="low")]),
    "lm studio.exe": ProcessFact(
        "LM Studio", "Desktop app for running local models.", "ai",
        "LM Studio", killable=True,
        common_causes=["A model loaded in the built-in server"]),

    "docker desktop.exe": ProcessFact(
        "Docker Desktop", "Container platform with a Linux VM behind it.",
        "dev", "Docker", killable=True,
        common_causes=["The VM's memory reservation",
                       "A container in a restart loop"],
        fixes=[_f("Cap the VM's memory",
                  "Docker's Linux VM takes a fixed share of RAM. Settings > "
                  "Resources.", risk="low")]),
    "vmmem": ProcessFact(
        "WSL / Hyper-V virtual machine memory",
        "Memory used by WSL2 or a Hyper-V VM, shown as one process.",
        "dev", "Microsoft", killable=False,
        common_causes=["WSL2 taking up to half the machine's RAM by default"],
        fixes=[_f("Cap WSL2 memory",
                  "Create %UserProfile%\\.wslconfig with a memory= line, then "
                  "`wsl --shutdown`.", risk="low")]),
    "vmmemwsl": ProcessFact(
        "WSL virtual machine memory", "Memory used by WSL2.", "dev",
        "Microsoft", killable=False,
        fixes=[_f("Cap WSL2 memory",
                  "Create %UserProfile%\\.wslconfig with a memory= line, then "
                  "`wsl --shutdown`.", risk="low")]),
    "steam.exe": ProcessFact(
        "Steam", "Game store and launcher.", "game", "Valve", killable=True,
        common_causes=["A download or shader pre-cache running"]),
    "searchprotocolhost.exe": ProcessFact(
        "Search Protocol Host", "Reads files for the search indexer.",
        "system", "Microsoft", killable=True),
    "searchfilterhost.exe": ProcessFact(
        "Search Filter Host", "Extracts text for the search indexer.",
        "system", "Microsoft", killable=True),
    "backgroundtaskhost.exe": ProcessFact(
        "Background Task Host", "Runs Store app background tasks.",
        "system", "Microsoft", killable=True),
    "gamebar.exe": ProcessFact(
        "Xbox Game Bar", "Game overlay and capture.", "game", "Microsoft",
        killable=True,
        fixes=[_f("Turn off Game Bar and background recording",
                  "Settings > Gaming > Xbox Game Bar, and Captures > "
                  "background recording.")]),
}


#: Names that are containers rather than identities — reporting them by name
#: alone is close to meaningless, so callers should dig for what is inside.
AMBIGUOUS = {"svchost.exe", "rundll32.exe", "dllhost.exe", "taskhostw.exe",
             "backgroundtaskhost.exe", "node.exe", "python.exe", "pythonw.exe",
             "java.exe", "conhost.exe", "wscript.exe", "cscript.exe",
             "msedgewebview2.exe", "electron.exe"}


#: What a process's memory *is*, for the purpose of telling someone whether
#: they can get any of it back. Derived from the category rather than tagged
#: on every entry, so adding a process to the table gets this for free.
#:
#:   system      Windows itself — not negotiable
#:   work        the things the user actually has open and is using
#:   background  agents, updaters, vendor tools — reclaimable, nothing breaks
#:   security    antivirus and EDR — reclaimable only by removing duplicates,
#:               and usually somebody else's decision on a managed machine
#:   managed     remote-access and RMM agents deployed by an IT provider
#:   ai          local model servers — often the largest single consumer, and
#:               entirely within the user's gift to unload
RECLAIM_BY_CATEGORY = {
    "system": "system", "security": "security", "remote": "managed",
    "oem": "background", "util": "background", "network": "background",
    "ai": "ai", "browser": "work", "office": "work", "comms": "work",
    "dev": "work", "sync": "work", "game": "work", "media": "work",
}

RECLAIM_LABELS = {
    "system": "Windows itself",
    "work": "what you have open",
    "background": "background agents and vendor tools",
    "security": "security software",
    "managed": "remote management agents",
    "ai": "local AI model servers",
    "unknown": "unidentified",
}

#: Classes whose memory can genuinely be handed back without losing work.
RECLAIMABLE = ("background", "ai")


def lookup(name: str) -> ProcessFact | None:
    return KNOWN.get((name or "").strip().lower())


def reclaim_class(name: str, has_window: bool = False,
                  session: int = 0) -> str:
    """Which bucket this process's memory belongs in.

    For an unrecognised process the session is the deciding evidence. Anything
    running in an interactive session was started by the person sitting there,
    directly or by something they opened, so it counts as their work; anything
    in session 0 is a service and stays "unknown".

    Unknown is deliberately never treated as reclaimable. Guessing
    optimistically would produce the exact failure this classification exists
    to prevent — telling somebody they can free four gigabytes and then not
    being able to.
    """
    fact = lookup(name)
    if fact is None:
        if has_window or session > 0:
            return "work"
        return "unknown"
    if fact.essential:
        return "system"
    return RECLAIM_BY_CATEGORY.get(fact.category, "unknown")


def is_known_leak(name: str) -> bool:
    fact = lookup(name)
    return bool(fact and fact.known_leak)


def describe(name: str) -> str:
    fact = lookup(name)
    return fact.role if fact else ""


def is_killable(name: str) -> bool:
    """Default to no.  An unknown process might be anything, including a
    service something else depends on, so silence is the safe answer."""
    fact = lookup(name)
    return bool(fact and fact.killable and not fact.essential)


def is_essential(name: str) -> bool:
    fact = lookup(name)
    return bool(fact and fact.essential)


def av_vendor(name: str) -> str:
    """Which real-time scanner this process belongs to, or ""."""
    return REALTIME_AV.get((name or "").strip().lower(), "")


def category(name: str) -> str:
    fact = lookup(name)
    return fact.category if fact else "app"
