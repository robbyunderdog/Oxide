// In release builds, don't open a console window alongside the app on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod net;

use eframe::egui;

/// Which backend to talk to. Priority: OXIDE_SERVER env var at runtime, then
/// OXIDE_SERVER at *compile* time (so we can bake the cloud URL into a release
/// build), then localhost for development.
fn server_url() -> String {
    std::env::var("OXIDE_SERVER")
        .ok()
        .or(option_env!("OXIDE_SERVER").map(String::from))
        .unwrap_or_else(|| "http://127.0.0.1:3000".into())
}

fn main() -> eframe::Result {
    // The tokio runtime lives for the whole program. `rt` must stay alive
    // until `run_native` returns, or all background tasks would be cancelled.
    let rt = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");

    // UI -> network: tokio channel (the network side awaits on it).
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    // network -> UI: std channel (the UI polls it with try_recv each frame).
    let (event_tx, event_rx) = std::sync::mpsc::channel();

    let server = server_url();
    let handle = rt.handle().clone();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Oxide")
            .with_inner_size([1000.0, 650.0])
            .with_min_inner_size([700.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Oxide",
        options,
        Box::new(move |cc| {
            // We need egui's Context so the network task can wake the UI.
            let ui_sender = net::UiSender::new(event_tx, cc.egui_ctx.clone());
            handle.spawn(net::run(cmd_rx, ui_sender, server));
            Ok(Box::new(app::App::new(cmd_tx, event_rx)))
        }),
    )
}
