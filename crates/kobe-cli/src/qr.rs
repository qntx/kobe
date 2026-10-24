//! Terminal QR rendering (Unicode half blocks, quiet zone 2).

use qrcode::QrCode;

use crate::CliResult;

const INDENT: &str = "      ";
const QUIET: i32 = 2;

/// Render `payload` as a terminal QR code: each character row encodes two
/// module rows via the upper-half block (▀ top-only, ▄ bottom-only, █ both,
/// space neither). Quiet zone of 2 modules on every side, 6-space indent.
pub(crate) fn render(payload: &str) -> CliResult<String> {
    let code = QrCode::new(payload.as_bytes()).map_err(|e| format!("QR encode: {e}"))?;
    Ok(matrix_to_text_impl(&code.to_colors(), code.width()))
}

fn matrix_to_text_impl(colors: &[qrcode::Color], width: usize) -> String {
    let w = i64::try_from(width).unwrap_or(0);
    let dark = |x: i64, y: i64| {
        if x < 0 || y < 0 || x >= w || y >= w {
            return false;
        }
        usize::try_from(y * w + x)
            .ok()
            .and_then(|i| colors.get(i))
            .is_some_and(|c| matches!(c, qrcode::Color::Dark))
    };
    let mut out = String::new();
    for y in (-i64::from(QUIET)..w + i64::from(QUIET)).step_by(2) {
        out.push_str(INDENT);
        for x in -i64::from(QUIET)..w + i64::from(QUIET) {
            out.push(match (dark(x, y), dark(x, y + 1)) {
                (true, true) => '\u{2588}',
                (true, false) => '\u{2580}',
                (false, true) => '\u{2584}',
                (false, false) => ' ',
            });
        }
        out.push('\n');
    }
    out
}

/// Render an already-encoded `QrCode` (used by --seedqr).
pub(crate) fn matrix_to_text_pub(code: &QrCode) -> String {
    matrix_to_text_impl(&code.to_colors(), code.width())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_blocks_and_indent() {
        let s = render("bc1qtest").expect("qr");
        assert!(s.contains('█') || s.contains('▀') || s.contains('▄'));
        assert!(s.starts_with("      "));

        // Decode the matrix with rqrr (a 2-module quiet zone is needed
        // for detection).
        let code = QrCode::new(b"bc1qtest").expect("qr");
        let q = 4;
        let size = code.width() + q * 2;
        let colors = code.to_colors();
        let mut img = rqrr::PreparedImage::prepare_from_greyscale(size, size, |x, y| {
            let dark = x >= q
                && y >= q
                && x - q < code.width()
                && y - q < code.width()
                && colors.get((y - q) * code.width() + (x - q)) == Some(&qrcode::Color::Dark);
            if dark { 0 } else { 255 }
        });
        let grids = img.detect_grids();
        assert_eq!(grids.len(), 1);
        let (_, content) = grids.first().expect("grid").decode().expect("decode");
        assert_eq!(content, "bc1qtest");
    }
}
