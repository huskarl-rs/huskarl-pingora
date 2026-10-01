//! Thread-local metric recorder for adapter tests.

#![allow(clippy::unwrap_used)]

pub(crate) type RecordedCounter = (String, Vec<(String, String)>, u64);

/// Runs `fut` on a current-thread runtime with a thread-local debugging recorder
/// installed, returning the captured counters as `(name, sorted (label, value) pairs,
/// count)`. Mirrors the harness in `huskarl-login`.
pub(crate) fn with_metrics<T>(fut: impl Future<Output = T>) -> (T, Vec<RecordedCounter>) {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let out = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    });
    let counters: Vec<RecordedCounter> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _unit, _desc, value)| {
            let DebugValue::Counter(count) = value else {
                return None;
            };
            let key = key.key();
            let mut labels: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_owned(), l.value().to_owned()))
                .collect();
            labels.sort();
            Some((key.name().to_owned(), labels, count))
        })
        .collect();
    if !cfg!(feature = "metrics") {
        assert!(
            !counters
                .iter()
                .any(|(name, _, _)| name == "huskarl.resource.check"
                    || name.starts_with("huskarl.pingora.")),
            "local metrics emitted with feature disabled: {counters:?}"
        );
    }
    (out, counters)
}

/// Checks the full label schema and value, including absence when disabled.
pub(crate) fn assert_counter(
    counters: &[RecordedCounter],
    metric: &str,
    labels: &[(&str, &str)],
    enabled_count: u64,
) {
    let mut expected: Vec<_> = labels
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    expected.sort();
    let actual = counters
        .iter()
        .find(|(name, labels, _)| name == metric && labels == &expected)
        .map_or(0, |(_, _, count)| *count);
    assert_eq!(
        actual,
        if cfg!(feature = "metrics") {
            enabled_count
        } else {
            0
        },
        "{metric} {expected:?}: {counters:?}"
    );
}
