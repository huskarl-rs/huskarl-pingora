//! Percent-escape decoding primitives shared by the path-confusion guard.
//!
//! The positional structural scanner ([`crate::structural`]) needs to read `%XX`
//! escapes, their overlong-UTF-8 forms (`%C0%AF`), and double-encoded forms
//! (`%252F`). This module owns that byte-level knowledge in one tested place, so each
//! new encoding the guard learns to recognise is a single change here rather than
//! logic duplicated across modules.
//!
//! Every function reads *at a position* in a byte slice and never allocates — the
//! callers (a per-request scan, a single-pass rewrite) drive the cursor.

/// Decode one hex digit (`0`–`9`, `a`–`f`, `A`–`F`) to its value, or `None`.
pub(crate) fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode the byte of a single `%XX` escape at `b[i]`, or `None` if `b[i]` does not
/// begin a complete escape (not a `%`, or fewer than two hex digits follow).
pub(crate) fn byte_at(b: &[u8], i: usize) -> Option<u8> {
    if b.get(i)? != &b'%' {
        return None;
    }
    let hi = hex_val(*b.get(i + 1)?)?;
    let lo = hex_val(*b.get(i + 2)?)?;
    Some(hi * 16 + lo)
}

/// Decode the inner byte of a *double*-encoded escape at `b[i]` — a `%25` wrapper
/// (so `byte_at` here is a literal `%`) followed by two hex digits naming the byte a
/// second decode pass would reveal (`%252F` → `/`). `None` unless `b[i]` begins
/// `%25` and two hex digits follow it.
pub(crate) fn double_byte_at(b: &[u8], i: usize) -> Option<u8> {
    if byte_at(b, i)? != b'%' {
        return None;
    }
    let hi = hex_val(*b.get(i + 3)?)?;
    let lo = hex_val(*b.get(i + 4)?)?;
    Some(hi * 16 + lo)
}

/// If a 2-, 3-, or 4-byte UTF-8 sequence whose bytes are all percent-encoded starts
/// at `b[i]` and decodes to an ASCII byte, return that byte and the number of input
/// bytes it spans (`%XX` ×N). Because the only targets that matter (`/`, `.`) are
/// ASCII, any multi-byte encoding of them is by definition *overlong* (non-shortest
/// form) — so this only ever returns `/` or `.`.
pub(crate) fn overlong_at(b: &[u8], i: usize) -> Option<(u8, usize)> {
    let lead = byte_at(b, i)?;
    let seq_len: usize = match lead {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => return None,
    };
    let mut cp = u32::from(lead & (0x7Fu8 >> seq_len));
    for k in 1..seq_len {
        let cont = byte_at(b, i + k * 3)?;
        if cont & 0xC0 != 0x80 {
            return None;
        }
        cp = (cp << 6) | u32::from(cont & 0x3F);
    }
    let decoded = u8::try_from(cp).ok()?;
    (decoded == b'/' || decoded == b'.').then_some((decoded, seq_len * 3))
}

/// Recognise a **fullwidth-form structural confusable** at `b[i]` — a character that
/// NFKC (compatibility) normalization folds to a path delimiter — in either its raw
/// UTF-8 form (`／` = `EF BC 8F`, 3 bytes) or its percent-encoded form (`%EF%BC%8F`, 9
/// bytes). Returns the folded ASCII byte and the number of input bytes the form spans,
/// or `None`.
///
/// The set is the Fullwidth Forms members that decompose to a delimiter — U+FF0F→`/`,
/// U+FF0E→`.`, U+FF1B→`;`, U+FF3C→`\` — all sharing the `EF BC` lead, so the third byte
/// selects the target. A backend that NFKC-normalizes the path before routing resolves
/// these to their ASCII class.
pub(crate) fn fullwidth_at(b: &[u8], i: usize) -> Option<(u8, usize)> {
    fn folded(third: u8) -> Option<u8> {
        match third {
            0x8F => Some(b'/'),
            0x8E => Some(b'.'),
            0x9B => Some(b';'),
            0xBC => Some(b'\\'),
            _ => None,
        }
    }
    // Raw UTF-8 `EF BC xx`.
    if b.get(i) == Some(&0xEF)
        && b.get(i + 1) == Some(&0xBC)
        && let Some(&third) = b.get(i + 2)
    {
        return folded(third).map(|a| (a, 3));
    }
    // Percent-encoded `%EF %BC %xx`.
    if byte_at(b, i) == Some(0xEF)
        && byte_at(b, i + 3) == Some(0xBC)
        && let Some(a) = byte_at(b, i + 6).and_then(folded)
    {
        return Some((a, 9));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_val_decodes_both_cases() {
        assert_eq!(hex_val(b'0'), Some(0));
        assert_eq!(hex_val(b'9'), Some(9));
        assert_eq!(hex_val(b'a'), Some(10));
        assert_eq!(hex_val(b'F'), Some(15));
        assert_eq!(hex_val(b'g'), None);
        assert_eq!(hex_val(b'%'), None);
    }

    #[test]
    fn byte_at_decodes_complete_escapes() {
        assert_eq!(byte_at(b"%2f", 0), Some(b'/'));
        assert_eq!(byte_at(b"%2F", 0), Some(b'/'));
        assert_eq!(byte_at(b"a%2eb", 1), Some(b'.'));
        assert_eq!(byte_at(b"%00", 0), Some(0));
        // not a `%`, or truncated/invalid escape
        assert_eq!(byte_at(b"abc", 0), None);
        assert_eq!(byte_at(b"%2", 0), None);
        assert_eq!(byte_at(b"%2g", 0), None);
    }

    #[test]
    fn double_byte_at_peels_one_layer() {
        // `%25` + `2F` = a double-encoded `/`.
        assert_eq!(double_byte_at(b"%252f", 0), Some(b'/'));
        assert_eq!(double_byte_at(b"%253B", 0), Some(b';'));
        assert_eq!(double_byte_at(b"%2500", 0), Some(0));
        // `%2F` is a single `/`, not a `%25` wrapper → None.
        assert_eq!(double_byte_at(b"%2f", 0), None);
        // `%25` with no inner hex pair → None.
        assert_eq!(double_byte_at(b"%25", 0), None);
        assert_eq!(double_byte_at(b"%25gg", 0), None);
    }

    #[test]
    fn overlong_at_decodes_2_3_4_byte_forms() {
        assert_eq!(overlong_at(b"%c0%af", 0), Some((b'/', 6)));
        assert_eq!(overlong_at(b"%C0%AE", 0), Some((b'.', 6)));
        assert_eq!(overlong_at(b"%e0%80%af", 0), Some((b'/', 9)));
        assert_eq!(overlong_at(b"%f0%80%80%af", 0), Some((b'/', 12)));
        // ordinary single-byte escape is not overlong
        assert_eq!(overlong_at(b"%2f", 0), None);
        // non-target overlong (overlong 'A') is ignored
        assert_eq!(overlong_at(b"%c1%81", 0), None);
        // truncated continuation
        assert_eq!(overlong_at(b"%c0%a", 0), None);
    }

    #[test]
    fn fullwidth_at_decodes_raw_and_percent_forms() {
        // Raw UTF-8 fullwidth forms (3 bytes each).
        assert_eq!(fullwidth_at("／".as_bytes(), 0), Some((b'/', 3)));
        assert_eq!(fullwidth_at("．".as_bytes(), 0), Some((b'.', 3)));
        assert_eq!(fullwidth_at("；".as_bytes(), 0), Some((b';', 3)));
        assert_eq!(fullwidth_at("＼".as_bytes(), 0), Some((b'\\', 3)));
        // Percent-encoded (9 bytes), case-insensitive hex.
        assert_eq!(fullwidth_at(b"%EF%BC%8F", 0), Some((b'/', 9)));
        assert_eq!(fullwidth_at(b"%ef%bc%8e", 0), Some((b'.', 9)));
        // A fullwidth *letter* (U+FF21 `Ａ`) is not a structural confusable.
        assert_eq!(fullwidth_at("Ａ".as_bytes(), 0), None);
        // Ordinary input.
        assert_eq!(fullwidth_at(b"abc", 0), None);
        assert_eq!(fullwidth_at(b"%2f", 0), None);
    }
}
