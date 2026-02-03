use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ParallelConfig {
    pub workers: usize,
    pub cpu_count: usize,
    pub rayon_threads: usize,
    pub par_threshold: usize,
    pub allow_parallel: bool,
}

impl ParallelConfig {
    pub fn new(cpu_count: usize, rayon_threads: usize, par_threshold: Option<usize>) -> Self {
        let par_threshold = match par_threshold {
            Some(v) if v > 0 => v,
            _ => std::cmp::max(8, 4 * rayon_threads),
        };
        let allow_parallel = cpu_count > 1 && rayon_threads > 1;
        Self {
            workers: 1,
            cpu_count,
            rayon_threads,
            par_threshold,
            allow_parallel,
        }
    }
}

/// Initialize worker threads and build Rayon thread pool.
/// Returns ParallelConfig with all tuning parameters.
pub fn init_parallelism(
    workers_override: Option<usize>,
    rayon_override: Option<usize>,
    par_threshold_override: Option<usize>,
) -> ParallelConfig {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let default_workers = std::cmp::max(1, cpu_count / 2);
    let workers = std::cmp::max(1, workers_override.unwrap_or(default_workers));

    let rayon_threads_override = rayon_override.or_else(|| {
        std::env::var("RAYON_NUM_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
    });
    let default_rayon = std::cmp::max(1, cpu_count.saturating_sub(workers));
    let rayon_threads = std::cmp::max(1, rayon_threads_override.unwrap_or(default_rayon));

    rayon::ThreadPoolBuilder::new()
        .num_threads(rayon_threads)
        .build_global()
        .expect("Failed to build Rayon thread pool");

    let mut parallel_config = ParallelConfig::new(cpu_count, rayon_threads, par_threshold_override);
    parallel_config.workers = workers;

    parallel_config
}
