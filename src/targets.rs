pub fn matches(name: &str, usb: bool) -> bool {
    let names: &[&str] = if usb {
        &[
            "WhatsApp", "Mail", "Messages", "Safari", "Files", "Books", "Telegram", "Slack",
            "Notes", "Preview",
        ]
    } else {
        &[
            "WhatsApp",
            "Mail",
            "Message",
            "Notes",
            "Pages",
            "Books",
            "Preview",
            "Safari",
            "Chrome",
            "Slack",
            "Telegram",
            "Discord",
            "QuickLookUIService",
            "com.apple.quicklook.ThumbnailsAgent",
            "qlmanage",
            "sips",
            "QuickLookExtension",
            "hotcell",
        ]
    };
    let lower = name.to_lowercase();
    names.iter().any(|n| lower.contains(&n.to_lowercase()))
}
