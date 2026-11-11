package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "JSON Sanitizer",
		Width:     960,
		Height:    720,
		MinWidth:  560,
		MinHeight: 420,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		// Transparent so the page's own light/dark background shows from the first frame.
		BackgroundColour: &options.RGBA{R: 0, G: 0, B: 0, A: 0},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []interface{}{app},
		Mac: &mac.Options{
			TitleBar:             mac.TitleBarHiddenInset(), // header doubles as the title bar
			WebviewIsTransparent: true,
			Appearance:           mac.DefaultAppearance, // follow system light/dark
			About: &mac.AboutInfo{
				Title:   "JSON Sanitizer",
				Message: "Strips personal data from JSON locally with Qwen via Ollama.",
			},
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
