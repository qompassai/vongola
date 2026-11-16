//! Pure ratatui widget constructors over [`ScreenModel`]s: no
//! state, no I/O — the same constructors the full-screen loop
//! draws and the `TestBackend` tests render.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::screens::ScreenModel;

/// Draw one screen model into `area`: a bordered block titled
/// with the model title, body lines wrapped.
pub fn draw_model(frame: &mut Frame, area: Rect, model: &ScreenModel) {
    let text = model.lines.join("\n");
    let widget = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(model.title.clone()),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, area);
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::App;
    use crate::facade::FakeFacade;

    fn render_to_string(app: &App<FakeFacade>) -> String {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let model = app.model();
        terminal
            .draw(|frame| {
                let area = frame.area();
                draw_model(frame, area, &model);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn validation_headless_render_shows_overview() {
        let mut app = App::new(FakeFacade::healthy());
        app.refresh_status().unwrap();
        let text = render_to_string(&app);
        assert!(text.contains("Overview"), "{text}");
        assert!(text.contains("vongola-mcp"), "{text}");
    }

    #[test]
    fn validation_headless_render_shows_each_screen() {
        let mut app = App::new(FakeFacade::healthy());
        app.refresh_status().unwrap();
        for (screen, needle) in [
            (crate::Screen::Workflows, "cert_status"),
            (crate::Screen::Fleet, "Fleet"),
            (crate::Screen::Media, "Unavailable"),
            (crate::Screen::Log, "Log"),
        ] {
            app.screen = screen;
            let text = render_to_string(&app);
            assert!(text.contains(needle), "{}: {text}", screen.name());
        }
    }
}
