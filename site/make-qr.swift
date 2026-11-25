// Renders a styled QR code PNG for the website's donation section:
//   swift site/make-qr.swift <text> <out.png> <hex color> <badge label>
// Rounded modules, rounded finder "eyes" in the coin's color, and a badge in the middle. Error correction is H
// (30 %), so the badge does not stop it from scanning. The badge is drawn into the image, so the file you scan
// while reviewing is exactly what visitors get. Check it decodes with CoreImage after any change.
import AppKit
import CoreImage

let args = CommandLine.arguments
guard args.count == 5 else {
    print("usage: make-qr.swift <text> <out.png> <hex color> <badge label>")
    exit(1)
}
let (text, out, hex, label) = (args[1], args[2], args[3], args[4])

func color(_ hex: String) -> CGColor {
    let v = UInt32(hex.trimmingCharacters(in: CharacterSet(charactersIn: "#")), radix: 16) ?? 0
    return CGColor(srgbRed: CGFloat((v >> 16) & 0xFF) / 255, green: CGFloat((v >> 8) & 0xFF) / 255, blue: CGFloat(v & 0xFF) / 255, alpha: 1)
}

// 1. Module matrix from CoreImage (one pixel per module, with CoreImage's own quiet zone).
let filter = CIFilter(name: "CIQRCodeGenerator")!
filter.setValue(Data(text.utf8), forKey: "inputMessage")
filter.setValue("H", forKey: "inputCorrectionLevel")
let ci = filter.outputImage!
let ciContext = CIContext()
let cg = ciContext.createCGImage(ci, from: ci.extent)!
let w = cg.width, h = cg.height
var pixels = [UInt8](repeating: 0, count: w * h)
let gray = CGContext(data: &pixels, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w,
                     space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue)!
gray.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))
// Row 0 of `pixels` is the top row of the image.
func dark(_ x: Int, _ y: Int) -> Bool { x >= 0 && y >= 0 && x < w && y < h && pixels[y * w + x] < 128 }

// Bounds of the code itself (without the quiet zone).
var minX = w, minY = h, maxX = 0, maxY = 0
for y in 0..<h { for x in 0..<w where dark(x, y) { minX = min(minX, x); minY = min(minY, y); maxX = max(maxX, x); maxY = max(maxY, y) } }
let n = maxX - minX + 1 // modules per side

// 2. Draw.
let module: CGFloat = 24
let margin: CGFloat = 2 * module
let size = CGFloat(n) * module + 2 * margin
let ctx = CGContext(data: nil, width: Int(size), height: Int(size), bitsPerComponent: 8, bytesPerRow: 0,
                    space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.translateBy(x: 0, y: size)
ctx.scaleBy(x: 1, y: -1) // top-left origin, like the matrix

let accent = color(hex)
let ink = color("#0f172a")
ctx.setFillColor(CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 1))
ctx.addPath(CGPath(roundedRect: CGRect(x: 0, y: 0, width: size, height: size), cornerWidth: module * 1.6, cornerHeight: module * 1.6, transform: nil))
ctx.fillPath()

func cell(_ i: Int, _ j: Int) -> CGRect {
    CGRect(x: margin + CGFloat(i) * module, y: margin + CGFloat(j) * module, width: module, height: module)
}
let finders = [(0, 0), (n - 7, 0), (0, n - 7)]
func inFinder(_ i: Int, _ j: Int) -> Bool { finders.contains { i >= $0.0 && i < $0.0 + 7 && j >= $0.1 && j < $0.1 + 7 } }

// Badge area in the middle, kept clear of modules (about 22 % of the width).
let badgeModules = Int((Double(n) * 0.22).rounded(.up)) | 1
let b0 = (n - badgeModules) / 2
func inBadge(_ i: Int, _ j: Int) -> Bool { i >= b0 && i < b0 + badgeModules && j >= b0 && j < b0 + badgeModules }

ctx.setFillColor(ink)
for j in 0..<n {
    for i in 0..<n where dark(minX + i, minY + j) && !inFinder(i, j) && !inBadge(i, j) {
        let r = cell(i, j).insetBy(dx: module * 0.08, dy: module * 0.08)
        ctx.addPath(CGPath(roundedRect: r, cornerWidth: module * 0.32, cornerHeight: module * 0.32, transform: nil))
    }
}
ctx.fillPath()

// Finder eyes: rounded ring + rounded center, in the coin's color.
for (fi, fj) in finders {
    let outer = cell(fi, fj).union(cell(fi + 6, fj + 6))
    let ring = CGMutablePath()
    ring.addRoundedRect(in: outer, cornerWidth: module * 2, cornerHeight: module * 2)
    ring.addRoundedRect(in: outer.insetBy(dx: module, dy: module), cornerWidth: module * 1.2, cornerHeight: module * 1.2)
    ctx.addPath(ring)
    ctx.setFillColor(accent)
    ctx.fillPath(using: .evenOdd)
    let inner = cell(fi + 2, fj + 2).union(cell(fi + 4, fj + 4))
    ctx.addPath(CGPath(roundedRect: inner, cornerWidth: module * 0.9, cornerHeight: module * 0.9, transform: nil))
    ctx.fillPath()
}

// Badge: white rounded square with a colored circle and the label.
let badgeRect = cell(b0, b0).union(cell(b0 + badgeModules - 1, b0 + badgeModules - 1))
let circle = badgeRect.insetBy(dx: module * 0.6, dy: module * 0.6)
ctx.setFillColor(accent)
ctx.fillEllipse(in: circle)
ctx.saveGState()
ctx.scaleBy(x: 1, y: -1) // text draws bottom-up
ctx.translateBy(x: 0, y: -size)
let nsctx = NSGraphicsContext(cgContext: ctx, flipped: false)
NSGraphicsContext.current = nsctx
let fontSize = circle.width * (label.count <= 1 ? 0.62 : 0.34)
let attrs: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: fontSize, weight: .heavy), .foregroundColor: NSColor.white]
let str = NSAttributedString(string: label, attributes: attrs)
let ts = str.size()
let flippedCircle = CGRect(x: circle.minX, y: size - circle.maxY, width: circle.width, height: circle.height)
str.draw(at: CGPoint(x: flippedCircle.midX - ts.width / 2, y: flippedCircle.midY - ts.height / 2))
ctx.restoreGState()

let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
print("wrote \(out) (\(n)×\(n) modules)")
