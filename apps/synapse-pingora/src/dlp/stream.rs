//! Streaming DLP Scanner
//!
//! Allows scanning arbitrarily large streams of data without buffering the entire
//! content in memory. Handles patterns that cross chunk boundaries using an overlap buffer.

use super::scanner::{DlpConfig, DlpConfigError, DlpScanner, ScanResult, SensitiveDataType};
use std::collections::HashSet;
use std::sync::Arc;

/// Default overlap size (should be larger than the longest expected pattern)
const DEFAULT_OVERLAP_SIZE: usize = 1024; // 1KB

/// Default maximum buffer size (16MB)
const DEFAULT_MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// Safety margin added to auto-calculated overlap
const OVERLAP_SAFETY_MARGIN: usize = 64;

/// Error type for streaming scanner operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamingError {
    /// Buffer would exceed maximum allowed size
    BufferOverflow {
        current: usize,
        incoming: usize,
        max: usize,
    },
    /// Configuration error
    Config(DlpConfigError),
}

impl std::fmt::Display for StreamingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferOverflow {
                current,
                incoming,
                max,
            } => {
                write!(
                    f,
                    "buffer overflow: current {} + incoming {} > max {}",
                    current, incoming, max
                )
            }
            Self::Config(e) => write!(f, "config error: {}", e),
        }
    }
}

impl std::error::Error for StreamingError {}

impl From<DlpConfigError> for StreamingError {
    fn from(e: DlpConfigError) -> Self {
        Self::Config(e)
    }
}

/// Streaming wrapper for DlpScanner
pub struct StreamingScanner {
    scanner: Arc<DlpScanner>,
    buffer: Vec<u8>,
    overlap_size: usize,
    max_buffer_size: usize,
    /// Tracks bytes that have been fully processed and shifted out of buffer
    bytes_shifted: usize,
    accumulated_results: ScanResult,
    /// Track seen matches by (data_type, absolute_end_position) to deduplicate
    seen_matches: HashSet<(SensitiveDataType, usize)>,
}

impl StreamingScanner {
    /// Create a new streaming scanner using an existing scanner configuration
    pub fn new(scanner: Arc<DlpScanner>) -> Self {
        Self {
            scanner,
            buffer: Vec::with_capacity(DEFAULT_OVERLAP_SIZE * 2),
            overlap_size: DEFAULT_OVERLAP_SIZE,
            max_buffer_size: DEFAULT_MAX_BUFFER_SIZE,
            bytes_shifted: 0,
            accumulated_results: ScanResult::default(),
            seen_matches: HashSet::new(),
        }
    }

    /// Create a streaming scanner with auto-calculated overlap based on pattern lengths
    pub fn with_auto_overlap(scanner: Arc<DlpScanner>, config: &DlpConfig) -> Self {
        let overlap = config.max_pattern_length() + OVERLAP_SAFETY_MARGIN;
        Self::new(scanner).with_overlap(overlap)
    }

    /// Set custom overlap size (max pattern length to detect across chunks)
    pub fn with_overlap(mut self, size: usize) -> Self {
        self.overlap_size = size;
        self
    }

    /// Set maximum buffer size (default 16MB)
    /// Returns error if a chunk would cause buffer to exceed this limit
    pub fn with_max_buffer_size(mut self, size: usize) -> Self {
        self.max_buffer_size = size;
        self
    }

    /// Get the current absolute stream position (bytes processed so far)
    pub fn bytes_processed(&self) -> usize {
        self.bytes_shifted + self.buffer.len()
    }

    /// Process a new chunk of data
    ///
    /// Returns error if the buffer would exceed max_buffer_size
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), StreamingError> {
        // Check buffer limit before appending
        let new_size = self.buffer.len() + chunk.len();
        if new_size > self.max_buffer_size {
            return Err(StreamingError::BufferOverflow {
                current: self.buffer.len(),
                incoming: chunk.len(),
                max: self.max_buffer_size,
            });
        }

        // Track how much data was in buffer before this chunk (the overlap region)
        let prev_len = self.buffer.len();

        // Append new chunk to buffer
        self.buffer.extend_from_slice(chunk);

        // Scan the current buffer
        let result = self.scanner.scan_bytes(&self.buffer);

        // Process matches
        if result.has_matches {
            for m in result.matches {
                // Calculate absolute stream position for this match
                let abs_start = self.bytes_shifted + m.start;
                let abs_end = self.bytes_shifted + m.end;

                // Deduplication: Skip if we've already seen this match
                // A match is considered duplicate if same type ends at same absolute position
                let match_key = (m.data_type, abs_end);
                if self.seen_matches.contains(&match_key) {
                    continue;
                }

                // Only report matches that end in the "new" part of the buffer
                // (i.e., end index > prev_len relative to current buffer)
                // This prevents reporting the same match twice when it's fully in overlap
                if m.end > prev_len {
                    self.seen_matches.insert(match_key);

                    // Create match with absolute stream offset
                    let mut new_match = m;
                    new_match.stream_offset = Some(abs_start);
                    // Update start/end to absolute positions
                    new_match.start = abs_start;
                    new_match.end = abs_end;

                    self.accumulated_results.matches.push(new_match);
                    self.accumulated_results.match_count += 1;
                    self.accumulated_results.has_matches = true;
                }
            }
        }

        // Prepare buffer for next chunk: keep only overlap
        if self.buffer.len() > self.overlap_size {
            let keep_start = self.buffer.len() - self.overlap_size;

            // Track how many bytes we're shifting out
            self.bytes_shifted += keep_start;

            // Keep only the tail
            self.buffer.drain(0..keep_start);
        }

        Ok(())
    }

    /// Finish the stream and get final results
    #[must_use = "final scan results should be processed"]
    pub fn finish(mut self) -> ScanResult {
        // Update total bytes scanned
        self.accumulated_results.content_length = self.bytes_shifted + self.buffer.len();
        self.accumulated_results.scanned = true;
        self.accumulated_results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlp::DlpConfig;

    #[test]
    fn test_streaming_split_pattern() {
        let config = DlpConfig {
            enabled: true,
            ..Default::default()
        };
        let scanner = Arc::new(DlpScanner::new(config));
        let mut stream = StreamingScanner::new(scanner);

        // "Credit card: 4532015112830366" split across chunks
        stream.update(b"Credit card: 45320151").unwrap();
        stream.update(b"12830366 is valid.").unwrap();

        let result = stream.finish();

        assert!(result.has_matches);
        assert_eq!(result.match_count, 1);
        assert_eq!(
            result.matches[0].data_type,
            crate::dlp::SensitiveDataType::CreditCard
        );
        // Should have stream offset set
        assert!(result.matches[0].stream_offset.is_some());
    }

    #[test]
    fn test_streaming_no_duplicates() {
        let config = DlpConfig {
            enabled: true,
            ..Default::default()
        };
        let scanner = Arc::new(DlpScanner::new(config));
        let mut stream = StreamingScanner::new(scanner);

        // Pattern fits in first chunk, but is retained in overlap
        // Should not be reported twice
        let chunk1 = b"Credit card: 4532015112830366 ";
        let chunk2 = b"next chunk data";

        stream.update(chunk1).unwrap();
        stream.update(chunk2).unwrap();

        let result = stream.finish();

        assert_eq!(result.match_count, 1, "Should detect exactly once");
    }

    #[test]
    fn test_buffer_overflow_protection() {
        let config = DlpConfig {
            enabled: true,
            ..Default::default()
        };
        let scanner = Arc::new(DlpScanner::new(config));
        let mut stream = StreamingScanner::new(scanner).with_max_buffer_size(100);

        // First small chunk should work
        assert!(stream.update(b"small data").is_ok());

        // Large chunk should fail
        let large_chunk = vec![b'x'; 200];
        let result = stream.update(&large_chunk);
        assert!(matches!(result, Err(StreamingError::BufferOverflow { .. })));
    }

    #[test]
    fn test_stream_position_tracking() {
        let config = DlpConfig {
            enabled: true,
            ..Default::default()
        };
        let scanner = Arc::new(DlpScanner::new(config));
        let mut stream = StreamingScanner::new(scanner).with_overlap(50);

        // Send data in chunks
        stream.update(b"prefix data here ").unwrap(); // 17 bytes
        stream.update(b"Card: 4532015112830366").unwrap(); // Card at position ~17

        let result = stream.finish();

        assert!(result.has_matches);
        let credit_card = &result.matches[0];
        assert!(credit_card.stream_offset.is_some());
        // The credit card number starts after "Card: " which is at ~17 + 6 = 23
        let offset = credit_card.stream_offset.unwrap();
        assert!(offset >= 17, "Stream offset {} should be >= 17", offset);
    }

    #[test]
    fn test_auto_overlap() {
        let config = DlpConfig {
            enabled: true,
            custom_keywords: Some(vec!["VeryLongSecretKeyword123456789".to_string()]),
            ..Default::default()
        };
        let scanner = Arc::new(DlpScanner::new(config.clone()));
        let stream = StreamingScanner::with_auto_overlap(scanner, &config);

        // Auto overlap should be at least max_pattern_length + safety margin
        let expected_min = config.max_pattern_length() + OVERLAP_SAFETY_MARGIN;
        assert!(
            stream.overlap_size >= expected_min,
            "overlap {} should be >= {}",
            stream.overlap_size,
            expected_min
        );
    }
}
