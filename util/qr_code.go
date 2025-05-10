package util

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/skip2/go-qrcode"
)

func GenerateQRCode(data string) string {
	qr, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		return ""
	}
	return qr.ToString(false)
}

// SaveQRCodeToFile generates a QR code from the provided data and saves it to the specified file path as a PNG image
// size: the size of the QR code in pixels
// Returns error if failed
func SaveQRCodeToFile(data string, filePath string, size int) error {
	return qrcode.WriteFile(data, qrcode.Medium, size, filePath)
}

// DisplayQRCodeInConsole prints a QR code directly to the console
// It creates a text-based QR code and displays it with a title
func DisplayQRCodeInConsole(data string, title string) {
	qrCode := GenerateQRCode(data)
	if qrCode == "" {
		fmt.Println("Failed to generate QR code")
		return
	}

	if title != "" {
		fmt.Println(title)
		fmt.Println()
	}

	fmt.Println(qrCode)
}

// DisplayColoredQRCodeInConsole prints a QR code to the console with custom colors
// foregroundColor: color of the QR code blocks
// backgroundColor: color of the background (optional, default is terminal default)
// validColors: "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"
func DisplayColoredQRCodeInConsole(data string, title string, foregroundColor string) {
	qrCode := GenerateQRCode(data)
	if qrCode == "" {
		fmt.Println("Failed to generate QR code")
		return
	}

	if title != "" {
		fmt.Println(title)
		fmt.Println()
	}

	// Map colors to color.Attribute values
	colorMap := map[string]color.Attribute{
		"black":   color.FgBlack,
		"red":     color.FgRed,
		"green":   color.FgGreen,
		"yellow":  color.FgYellow,
		"blue":    color.FgBlue,
		"magenta": color.FgMagenta,
		"cyan":    color.FgCyan,
		"white":   color.FgWhite,
	}

	// Get color attribute or default to white
	fgColor, ok := colorMap[strings.ToLower(foregroundColor)]
	if !ok {
		fgColor = color.FgWhite
	}

	// Create colored printer
	colorPrinter := color.New(fgColor)

	// Print each line with color
	lines := strings.Split(qrCode, "\n")
	for _, line := range lines {
		colorPrinter.Println(line)
	}
}

// DisplayCustomQRCode creates a QR code with custom block characters and styling
// It allows for better visibility in different terminal environments
// blockChar: character to use for QR code blocks (e.g. "█", "■", "▓", "○", "#", etc.)
// foregroundColor: color of the QR code blocks (optional)
func DisplayCustomQRCode(data string, title string, blockChar string, foregroundColor string) {
	qr, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		fmt.Println("Failed to generate QR code")
		return
	}

	// If no block character provided, use default
	if blockChar == "" {
		blockChar = "█"
	}

	// Get QR code bitmap
	bitmap := qr.Bitmap()

	if title != "" {
		fmt.Println(title)
		fmt.Println()
	}

	// Map colors to color.Attribute values
	colorMap := map[string]color.Attribute{
		"black":   color.FgBlack,
		"red":     color.FgRed,
		"green":   color.FgGreen,
		"yellow":  color.FgYellow,
		"blue":    color.FgBlue,
		"magenta": color.FgMagenta,
		"cyan":    color.FgCyan,
		"white":   color.FgWhite,
	}

	// Get color attribute or default to no color
	var colorPrinter *color.Color
	if foregroundColor != "" {
		if fgColor, ok := colorMap[strings.ToLower(foregroundColor)]; ok {
			colorPrinter = color.New(fgColor)
		}
	}

	// Print the QR code line by line
	for y := range bitmap {
		var line strings.Builder
		for x := range bitmap[y] {
			if bitmap[y][x] {
				line.WriteString(blockChar)
			} else {
				line.WriteString(" ")
			}
		}

		if colorPrinter != nil {
			colorPrinter.Println(line.String())
		} else {
			fmt.Println(line.String())
		}
	}
}

// DisplayCompactQRCode displays a more compact QR code with smaller border
// It uses half-width characters to make the QR code appear smaller in the terminal
// borderSize: whether to show border (default is true)
func DisplayCompactQRCode(data string, title string, disableBorder bool, foregroundColor string) {
	// Create QR code with low recovery level for smaller size
	qr, err := qrcode.New(data, qrcode.Low)
	if err != nil {
		fmt.Println("Failed to generate QR code")
		return
	}

	// Set border visibility
	qr.DisableBorder = disableBorder

	// Get bitmap of QR code
	bitmap := qr.Bitmap()

	if title != "" {
		fmt.Println(title)
		fmt.Println()
	}

	// Map colors to color.Attribute values
	colorMap := map[string]color.Attribute{
		"black":   color.FgBlack,
		"red":     color.FgRed,
		"green":   color.FgGreen,
		"yellow":  color.FgYellow,
		"blue":    color.FgBlue,
		"magenta": color.FgMagenta,
		"cyan":    color.FgCyan,
		"white":   color.FgWhite,
	}

	// Get color attribute
	var colorPrinter *color.Color
	if foregroundColor != "" {
		if fgColor, ok := colorMap[strings.ToLower(foregroundColor)]; ok {
			colorPrinter = color.New(fgColor)
		}
	}

	// Use a smaller block character (half-width)
	blockChar := "▪"

	// Print QR code with compact characters
	for y := range bitmap {
		var line strings.Builder
		for x := range bitmap[y] {
			if bitmap[y][x] {
				line.WriteString(blockChar)
			} else {
				line.WriteString(" ")
			}
		}

		if colorPrinter != nil {
			colorPrinter.Println(line.String())
		} else {
			fmt.Println(line.String())
		}
	}
}

// DisplayMiniQRCode creates the smallest possible QR code for the given data
// Uses the smallest version that can fit the data with low error correction
// and a very tiny block character with no border
func DisplayMiniQRCode(data string, title string, foregroundColor string) {
	// Try to create QR with minimum version (1) and low error correction
	// This will be the smallest possible QR code
	qr, err := qrcode.NewWithForcedVersion(data, 1, qrcode.Low)
	if err != nil {
		// If version 1 fails, create with auto sizing but low recovery level
		qr, err = qrcode.New(data, qrcode.Low)
		if err != nil {
			fmt.Println("Failed to generate QR code")
			return
		}
	}

	// Disable the border for minimal size
	qr.DisableBorder = true

	// Get bitmap of QR code
	bitmap := qr.Bitmap()

	if title != "" {
		fmt.Println(title)
		fmt.Println()
	}

	// Map colors to color.Attribute values
	colorMap := map[string]color.Attribute{
		"black":   color.FgBlack,
		"red":     color.FgRed,
		"green":   color.FgGreen,
		"yellow":  color.FgYellow,
		"blue":    color.FgBlue,
		"magenta": color.FgMagenta,
		"cyan":    color.FgCyan,
		"white":   color.FgWhite,
	}

	// Get color attribute
	var colorPrinter *color.Color
	if foregroundColor != "" {
		if fgColor, ok := colorMap[strings.ToLower(foregroundColor)]; ok {
			colorPrinter = color.New(fgColor)
		}
	}

	// Use a very small block character
	blockChar := "•"

	// Print QR code with tiny block character
	for y := range bitmap {
		var line strings.Builder
		for x := range bitmap[y] {
			if bitmap[y][x] {
				line.WriteString(blockChar)
			} else {
				line.WriteString(" ")
			}
		}

		lineStr := line.String()
		if colorPrinter != nil {
			colorPrinter.Println(lineStr)
		} else {
			fmt.Println(lineStr)
		}
	}
}

// DisplaySuperCompactQRCode creates an ultra-compact QR code using double-density blocks
// This function combines 2x2 blocks into a single character for maximum density
// It creates the smallest possible QR code display for terminals that support Unicode blocks
func DisplaySuperCompactQRCode(data string, title string, foregroundColor string) {
	// Try to create QR with minimum version (1) and low error correction
	qr, err := qrcode.NewWithForcedVersion(data, 1, qrcode.Low)
	if err != nil {
		// If version 1 fails, create with auto sizing but low recovery level
		qr, err = qrcode.New(data, qrcode.Low)
		if err != nil {
			fmt.Println("Failed to generate QR code")
			return
		}
	}

	// Disable the border for minimal size
	qr.DisableBorder = true

	// Get bitmap of QR code
	bitmap := qr.Bitmap()

	if title != "" {
		fmt.Println(title)
		fmt.Println()
	}

	// Map colors to color.Attribute values
	colorMap := map[string]color.Attribute{
		"black":   color.FgBlack,
		"red":     color.FgRed,
		"green":   color.FgGreen,
		"yellow":  color.FgYellow,
		"blue":    color.FgBlue,
		"magenta": color.FgMagenta,
		"cyan":    color.FgCyan,
		"white":   color.FgWhite,
	}

	// Get color attribute
	var colorPrinter *color.Color
	if foregroundColor != "" {
		if fgColor, ok := colorMap[strings.ToLower(foregroundColor)]; ok {
			colorPrinter = color.New(fgColor)
		}
	}

	// Unicode block elements for 2x2 block combinations
	blockMap := map[string]string{
		"0000": " ", // No blocks
		"0001": "▗", // Bottom right only
		"0010": "▖", // Bottom left only
		"0011": "▄", // Bottom row
		"0100": "▝", // Top right only
		"0101": "▐", // Right column
		"0110": "▞", // Diagonal bottom left and top right
		"0111": "▟", // All except top left
		"1000": "▘", // Top left only
		"1001": "▚", // Diagonal top left and bottom right
		"1010": "▌", // Left column
		"1011": "▙", // All except top right
		"1100": "▀", // Top row
		"1101": "▜", // All except bottom left
		"1110": "▛", // All except bottom right
		"1111": "█", // All four blocks
	}

	// Process bitmap in 2x2 blocks
	height := len(bitmap)
	width := 0
	if height > 0 {
		width = len(bitmap[0])
	}

	// Ensure even dimensions by adding padding if needed
	if height%2 != 0 {
		// Add a row of false values
		row := make([]bool, width)
		bitmap = append(bitmap, row)
		height++
	}
	if width%2 != 0 {
		// Add a column of false values
		for i := range bitmap {
			bitmap[i] = append(bitmap[i], false)
		}
		width++
	}

	// Process the bitmap in 2x2 blocks
	for y := 0; y < height; y += 2 {
		var line strings.Builder

		for x := 0; x < width; x += 2 {
			// Get the 2x2 block values
			topLeft := getBitmapValue(bitmap, y, x)
			topRight := getBitmapValue(bitmap, y, x+1)
			bottomLeft := getBitmapValue(bitmap, y+1, x)
			bottomRight := getBitmapValue(bitmap, y+1, x+1)

			// Create the key for the block map
			key := boolToString(topLeft) + boolToString(topRight) +
				boolToString(bottomLeft) + boolToString(bottomRight)

			// Add the corresponding character
			line.WriteString(blockMap[key])
		}

		lineStr := line.String()
		if colorPrinter != nil {
			colorPrinter.Println(lineStr)
		} else {
			fmt.Println(lineStr)
		}
	}
}

// Helper function to safely get a bitmap value
func getBitmapValue(bitmap [][]bool, y, x int) bool {
	if y < 0 || y >= len(bitmap) || x < 0 || x >= len(bitmap[y]) {
		return false
	}
	return bitmap[y][x]
}

// Helper function to convert bool to string
func boolToString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
