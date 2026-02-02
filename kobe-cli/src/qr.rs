//! Terminal QR code rendering utilities.

use qrcode::QrCode;

/// Render a QR code to the terminal using Unicode block characters.
///
/// Uses half-block characters (▀▄█ ) to display two rows per line,
/// making the QR code more compact and square-looking in terminals.
pub fn render_to_terminal(data: &str) {
    let code = match QrCode::new(data) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to generate QR code: {e}");
            return;
        }
    };

    let colors = code.to_colors();
    let width = code.width();

    // Add quiet zone (2 modules)
    let quiet_zone = 2;
    let total_width = width + quiet_zone * 2;

    // Build the matrix with quiet zone
    let mut matrix: Vec<Vec<bool>> = Vec::new();

    // Top quiet zone
    for _ in 0..quiet_zone {
        matrix.push(vec![false; total_width]);
    }

    // QR code data rows
    for y in 0..width {
        let mut row = vec![false; quiet_zone];
        for x in 0..width {
            let is_dark = colors[y * width + x] == qrcode::Color::Dark;
            row.push(is_dark);
        }
        row.extend(vec![false; quiet_zone]);
        matrix.push(row);
    }

    // Bottom quiet zone
    for _ in 0..quiet_zone {
        matrix.push(vec![false; total_width]);
    }

    // Render using half-block characters
    // Each character represents 2 vertical pixels
    let height = matrix.len();
    let indent = "      ";

    println!();
    for y in (0..height).step_by(2) {
        print!("{indent}");
        for x in 0..total_width {
            let top = matrix[y][x];
            let bottom = if y + 1 < height {
                matrix[y + 1][x]
            } else {
                false
            };

            // ▀ = top half, ▄ = bottom half, █ = full, ' ' = empty
            let ch = match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            print!("{ch}");
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_does_not_panic() {
        // Just ensure it doesn't panic
        render_to_terminal("bc1qtest");
        render_to_terminal("0x1234567890abcdef1234567890abcdef12345678");
    }
}
