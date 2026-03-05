use std::time::Instant;

use crate::metrics::MetricsRegistry;

/// Metrics sink for state-transition/signature-import instrumentation.
///
/// This keeps consensus logic decoupled from the concrete metrics backend while
/// allowing a no-op implementation when metrics are disabled.
pub(crate) trait TransitionMetricsSink {
    fn observe_slots_processing_time(&self, start: Instant);
    fn add_slots_processed(&self, n: u64);
    fn observe_attestations_processing_time(&self, start: Instant);
    fn add_attestations_processed(&self, n: u64);
    fn observe_block_processing_time(&self, start: Instant);
    fn inc_finalizations_success(&self);
    fn observe_state_transition_time(&self, start: Instant);
}

/// No-op sink used when metrics are disabled.
pub(crate) struct NoopTransitionMetricsSink;

impl TransitionMetricsSink for NoopTransitionMetricsSink {
    #[inline]
    fn observe_slots_processing_time(&self, _start: Instant) {}

    #[inline]
    fn add_slots_processed(&self, _n: u64) {}

    #[inline]
    fn observe_attestations_processing_time(&self, _start: Instant) {}

    #[inline]
    fn add_attestations_processed(&self, _n: u64) {}

    #[inline]
    fn observe_block_processing_time(&self, _start: Instant) {}

    #[inline]
    fn inc_finalizations_success(&self) {}

    #[inline]
    fn observe_state_transition_time(&self, _start: Instant) {}
}

impl TransitionMetricsSink for MetricsRegistry {
    #[inline]
    fn observe_slots_processing_time(&self, start: Instant) {
        self.state_transition_slots_processing_time
            .observe_duration(start);
    }

    #[inline]
    fn add_slots_processed(&self, n: u64) {
        self.slots_processed_total.add(n);
    }

    #[inline]
    fn observe_attestations_processing_time(&self, start: Instant) {
        self.state_transition_attestations_processing_time
            .observe_duration(start);
    }

    #[inline]
    fn add_attestations_processed(&self, n: u64) {
        self.attestations_processed_total.add(n);
    }

    #[inline]
    fn observe_block_processing_time(&self, start: Instant) {
        self.state_transition_block_processing_time
            .observe_duration(start);
    }

    #[inline]
    fn inc_finalizations_success(&self) {
        self.finalizations_success_total.inc();
    }

    #[inline]
    fn observe_state_transition_time(&self, start: Instant) {
        self.state_transition_time.observe_duration(start);
    }
}
