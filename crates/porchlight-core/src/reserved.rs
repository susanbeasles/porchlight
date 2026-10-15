//! Interfaces reserved for v1 and v2 (SPEC §10). Define the shape, implement nothing.

use crate::schema::Event;

/// Context handed to a scorer. Filled in by v1.
#[derive(Debug, Default, Clone)]
pub struct ScoringContext {}

/// Per-window anomaly score. Filled in by v1.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowScore {
    pub first_event_id: u64,
    pub last_event_id: u64,
    pub score: f64,
}

/// Dense feature vector. Filled in by v1.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct FeatureVector(pub Vec<f32>);

/// Query access to the graphs and inventory. Lands in M4; empty until then.
#[derive(Debug, Default, Clone)]
pub struct Context {}

/// A learned baseline. Filled in by v1 (personal) and v2 (community).
#[derive(Debug, Default, Clone)]
pub struct Baseline {}

pub trait AnomalyScorer {
    fn score(&self, window: &[Event], context: &ScoringContext) -> Vec<WindowScore>;
}

pub trait FeatureExtractor {
    fn features(&self, event: &Event, context: &Context) -> FeatureVector;
}

pub trait BaselineProvider {
    fn personal(&self) -> Option<&Baseline>;
    fn community(&self) -> Option<&Baseline>;
}
