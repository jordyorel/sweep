// Draws Sweep's app icon (1024×1024 PNG) with Core Graphics: `swift macos/icon/make-icon.swift out.png`.
// macos/build-app.sh turns it into AppIcon.icns. Original artwork: a shield with a sweeping stroke and a sparkle.
import AppKit

let size: CGFloat = 1024
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon.png"
let cs = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: Int(size), height: Int(size), bitsPerComponent: 8, bytesPerRow: 0,
                    space: cs, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!

func rgb(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: a)
}

// Body: Apple's icon grid (824 pt squircle inside 1024, ~185 pt corner radius), with a soft drop shadow.
let body = CGRect(x: 100, y: 100, width: 824, height: 824)
let bodyPath = CGPath(roundedRect: body, cornerWidth: 185, cornerHeight: 185, transform: nil)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: rgb(0x000000, 0.35))
ctx.addPath(bodyPath); ctx.setFillColor(rgb(0x0B3B6E)); ctx.fillPath()
ctx.restoreGState()
ctx.saveGState()
ctx.addPath(bodyPath); ctx.clip()
let bg = CGGradient(colorsSpace: cs, colors: [rgb(0x2DD4BF), rgb(0x0EA5E9), rgb(0x1E3A8A)] as CFArray, locations: [0, 0.45, 1])!
ctx.drawLinearGradient(bg, start: CGPoint(x: 200, y: 924), end: CGPoint(x: 824, y: 100), options: [])
// Subtle top highlight.
let hl = CGGradient(colorsSpace: cs, colors: [rgb(0xFFFFFF, 0.22), rgb(0xFFFFFF, 0)] as CFArray, locations: [0, 1])!
ctx.drawLinearGradient(hl, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 600), options: [])
ctx.restoreGState()

// Shield.
let shield = CGMutablePath()
shield.move(to: CGPoint(x: 512, y: 800))
shield.addCurve(to: CGPoint(x: 300, y: 720), control1: CGPoint(x: 440, y: 760), control2: CGPoint(x: 370, y: 735))
shield.addCurve(to: CGPoint(x: 512, y: 215), control1: CGPoint(x: 290, y: 470), control2: CGPoint(x: 380, y: 300))
shield.addCurve(to: CGPoint(x: 724, y: 720), control1: CGPoint(x: 644, y: 300), control2: CGPoint(x: 734, y: 470))
shield.addCurve(to: CGPoint(x: 512, y: 800), control1: CGPoint(x: 654, y: 735), control2: CGPoint(x: 584, y: 760))
shield.closeSubpath()
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 24, color: rgb(0x0B1F4D, 0.45))
ctx.addPath(shield); ctx.setFillColor(rgb(0xFFFFFF)); ctx.fillPath()
ctx.restoreGState()
ctx.saveGState()
ctx.addPath(shield); ctx.clip()
let sg = CGGradient(colorsSpace: cs, colors: [rgb(0xFFFFFF), rgb(0xE0F2FE)] as CFArray, locations: [0, 1])!
ctx.drawLinearGradient(sg, start: CGPoint(x: 512, y: 800), end: CGPoint(x: 512, y: 215), options: [])
ctx.restoreGState()

// Sweeping stroke: three tapered arcs, like a brush passing over the shield.
func sweep(_ y: CGFloat, _ width: CGFloat, _ alpha: CGFloat) {
    let p = CGMutablePath()
    p.move(to: CGPoint(x: 360, y: y - 40))
    p.addQuadCurve(to: CGPoint(x: 650, y: y + 70), control: CGPoint(x: 470, y: y + 70))
    ctx.addPath(p)
    ctx.setLineCap(.round)
    ctx.setLineWidth(width)
    ctx.setStrokeColor(rgb(0x0EA5E9, alpha))
    ctx.strokePath()
}
ctx.saveGState()
ctx.addPath(shield.copy(using: nil)!); ctx.clip() // keep the strokes inside the shield
sweep(560, 46, 1)
sweep(470, 34, 0.75)
sweep(390, 24, 0.5)
ctx.restoreGState()

// Sparkle (four-point star) at the end of the sweep.
func sparkle(_ c: CGPoint, _ r: CGFloat, _ color: CGColor) {
    let p = CGMutablePath()
    let k: CGFloat = 0.22
    p.move(to: CGPoint(x: c.x, y: c.y + r))
    p.addQuadCurve(to: CGPoint(x: c.x + r, y: c.y), control: CGPoint(x: c.x + r * k, y: c.y + r * k))
    p.addQuadCurve(to: CGPoint(x: c.x, y: c.y - r), control: CGPoint(x: c.x + r * k, y: c.y - r * k))
    p.addQuadCurve(to: CGPoint(x: c.x - r, y: c.y), control: CGPoint(x: c.x - r * k, y: c.y - r * k))
    p.addQuadCurve(to: CGPoint(x: c.x, y: c.y + r), control: CGPoint(x: c.x - r * k, y: c.y + r * k))
    ctx.addPath(p); ctx.setFillColor(color); ctx.fillPath()
}
sparkle(CGPoint(x: 668, y: 668), 62, rgb(0xFBBF24))
sparkle(CGPoint(x: 735, y: 575), 26, rgb(0xFFFFFF))

let img = ctx.makeImage()!
let rep = NSBitmapImageRep(cgImage: img)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
print("wrote \(out)")
