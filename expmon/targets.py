"""Target process discovery — which processes actually render untrusted files."""

TARGET_PROCS = {
    "macos": [
        # delivery channels / document processors
        "WhatsApp",
        "Mail", "Message", "Notes", "Pages", "Books",
        "Preview", "Safari", "Chrome", "Slack", "Telegram", "Discord",
        # Apple system renderers
        "QuickLookUIService",
        "com.apple.quicklook.ThumbnailsAgent",
        "qlmanage",
        "sips",
        "QuickLookExtension",
    ],
    "ios": [
        "WhatsApp", "Mail", "Messages", "Safari", "Files", "Books",
        "Telegram", "Slack", "Notes", "Preview",
    ],
}


def matches(name: str, platform: str = "macos"):
    n = (name or "").lower()
    return any(t.lower() in n for t in TARGET_PROCS.get(platform, TARGET_PROCS["macos"]))
