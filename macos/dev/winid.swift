// Prints the window number of the first normal window owned by a process: `winid <pid>` (used by screenshot.sh).
import CoreGraphics
import Foundation
let pid = Int(CommandLine.arguments[1])!
let list = CGWindowListCopyWindowInfo([.optionAll, .excludeDesktopElements], kCGNullWindowID) as! [[String: Any]]
for w in list where (w[kCGWindowOwnerPID as String] as? Int) == pid && (w[kCGWindowLayer as String] as? Int) == 0 {
    if let b = w[kCGWindowBounds as String] as? [String: Any], (b["Height"] as? Double ?? 0) > 200 {
        print(w[kCGWindowNumber as String] as! Int); break
    }
}
