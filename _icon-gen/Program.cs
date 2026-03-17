using SkiaSharp;

// StreamHash NuGet package icon - 128x128 PNG
// Design: Hash symbol (#) with streaming/flow lines on a gradient background

const int size = 128;
const int padding = 8;

using var surface = SKSurface.Create(new SKImageInfo(size, size));
var canvas = surface.Canvas;

// Background - rounded rectangle with gradient
// Deep blue to teal gradient representing data flow
using var bgPaint = new SKPaint {
	IsAntialias = true,
	Shader = SKShader.CreateLinearGradient(
		new SKPoint(0, 0),
		new SKPoint(size, size),
		[new SKColor(0x1a, 0x56, 0xdb), new SKColor(0x0d, 0x9b, 0x8c)], // blue to teal
		null,
		SKShaderTileMode.Clamp)
};

// Draw rounded rectangle background
var bgRect = new SKRoundRect(new SKRect(0, 0, size, size), 20, 20);
canvas.DrawRoundRect(bgRect, bgPaint);

// Draw three flowing stream lines (representing streaming data)
using var streamPaint = new SKPaint {
	IsAntialias = true,
	Style = SKPaintStyle.Stroke,
	StrokeWidth = 3.0f,
	Color = new SKColor(0xff, 0xff, 0xff, 0x40), // semi-transparent white
	StrokeCap = SKStrokeCap.Round
};

// Stream line 1 - top curve
using var stream1 = new SKPath();
stream1.MoveTo(padding, 30);
stream1.CubicTo(35, 18, 90, 42, size - padding, 30);
canvas.DrawPath(stream1, streamPaint);

// Stream line 2 - middle curve
using var stream2 = new SKPath();
stream2.MoveTo(padding, size / 2);
stream2.CubicTo(40, 50, 85, 78, size - padding, size / 2);
canvas.DrawPath(stream2, streamPaint);

// Stream line 3 - bottom curve
using var stream3 = new SKPath();
stream3.MoveTo(padding, 98);
stream3.CubicTo(35, 86, 90, 110, size - padding, 98);
canvas.DrawPath(stream3, streamPaint);

// Draw the hash symbol "#" in the center
using var hashPaint = new SKPaint {
	IsAntialias = true,
	Color = SKColors.White,
	Style = SKPaintStyle.Stroke,
	StrokeWidth = 7.0f,
	StrokeCap = SKStrokeCap.Round
};

// Hash symbol dimensions
float cx = size / 2f;
float cy = size / 2f;
float hashW = 32; // half-width of hash
float hashH = 32; // half-height of hash
float offset = 11; // offset from center for lines

// Vertical lines of # (slightly tilted for style)
float tilt = 3f;
canvas.DrawLine(cx - offset - tilt, cy - hashH, cx - offset + tilt, cy + hashH, hashPaint);
canvas.DrawLine(cx + offset - tilt, cy - hashH, cx + offset + tilt, cy + hashH, hashPaint);

// Horizontal lines of #
canvas.DrawLine(cx - hashW, cy - offset, cx + hashW, cy - offset, hashPaint);
canvas.DrawLine(cx - hashW, cy + offset, cx + hashW, cy + offset, hashPaint);

// Small accent: streaming dots on the right side (data flowing out)
using var dotPaint = new SKPaint {
	IsAntialias = true,
	Color = new SKColor(0xff, 0xff, 0xff, 0xb0),
	Style = SKPaintStyle.Fill
};

canvas.DrawCircle(size - padding - 4, 30, 2.5f, dotPaint);
canvas.DrawCircle(size - padding - 4, size / 2f, 2.5f, dotPaint);
canvas.DrawCircle(size - padding - 4, 98, 2.5f, dotPaint);

// Save to PNG
using var image = surface.Snapshot();
using var data = image.Encode(SKEncodedImageFormat.Png, 100);

var outputPath = Path.Combine("..", "assets", "icon.png");
using var fileStream = File.OpenWrite(outputPath);
data.SaveTo(fileStream);

Console.WriteLine($"Icon saved to {Path.GetFullPath(outputPath)} ({data.Size} bytes)");
