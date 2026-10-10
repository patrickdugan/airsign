//! QR output: half-block characters for the text console (two modules per
//! character cell, so modules come out square in an 8x16 font), and PBM files
//! for tests that decode the code with a real scanner library.

use qrcode::render::unicode::Dense1x2;
use qrcode::{Color, EcLevel, QrCode, Version};

use crate::codec::CodecError;

fn build(data: &str, level: EcLevel) -> Result<QrCode, CodecError> {
    QrCode::with_error_correction_level(data.as_bytes(), level)
        .map_err(|e| CodecError(format!("QR encode: {e:?}")))
}

/// Light-on-dark terminals: draw light modules as blocks so the code reads as
/// dark-on-light to a camera.
pub fn render_terminal(data: &str) -> Result<String, CodecError> {
    let code = build(data, EcLevel::M)?;
    Ok(code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).quiet_zone(true).build())
}

pub fn render_seedqr_terminal(digits: &str) -> Result<String, CodecError> {
    let version = if digits.len() <= 48 { Version::Normal(2) } else { Version::Normal(3) };
    let code = QrCode::with_version(digits.as_bytes(), version, EcLevel::L)
        .map_err(|e| CodecError(format!("SeedQR encode: {e:?}")))?;
    Ok(code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).quiet_zone(true).build())
}

pub fn version_of(data: &str) -> Option<usize> {
    build(data, EcLevel::M).ok().map(|c| (c.width() - 17) / 4)
}

/// Plain PBM (P1) with a 4-module quiet zone, `scale` pixels per module.
pub fn pbm(data: &str, scale: usize) -> Result<String, CodecError> {
    let code = build(data, EcLevel::M)?;
    let w = code.width();
    let colors = code.to_colors();
    let size = (w + 8) * scale;
    let mut out = format!("P1\n{size} {size}\n");
    for y in 0..size {
        let my = (y / scale) as isize - 4;
        let mut row = String::with_capacity(size * 2);
        for x in 0..size {
            let mx = (x / scale) as isize - 4;
            let dark = mx >= 0
                && my >= 0
                && (mx as usize) < w
                && (my as usize) < w
                && colors[my as usize * w + mx as usize] == Color::Dark;
            row.push(if dark { '1' } else { '0' });
            row.push(' ');
        }
        out.push_str(row.trim_end());
        out.push('\n');
    }
    Ok(out)
}
